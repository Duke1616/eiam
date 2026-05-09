package user

import (
	"context"
	"fmt"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// dummyHash 用于防时序攻击的哑元哈希值
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("anti-timing-attack"), bcrypt.DefaultCost)

func (s *userService) Login(ctx context.Context, provider, username, password string) (domain.LoginResult, error) {
	if provider == "" || provider == string(domain.SourceLocal) {
		return s.loginLocal(ctx, username, password)
	}

	return s.loginWithProvider(ctx, provider, username, password)
}

func (s *userService) LoginWithoutPassword(ctx context.Context, uid int64) (domain.LoginResult, error) {
	u, err := s.repo.FindById(ctx, uid)
	if err != nil {
		return domain.LoginResult{}, err
	}
	return s.postLogin(ctx, u, false)
}

func (s *userService) loginLocal(ctx context.Context, username, password string) (domain.LoginResult, error) {
	localCfg, found := s.getLocalConfig(ctx)

	if found && localCfg.MaxFailedAttempts > 0 {
		isLocked, _ := s.repo.IsLocked(ctx, username)
		if isLocked {
			return domain.LoginResult{}, errs.ErrUserLocked
		}
	}

	u, err := s.repo.FindByUsername(ctx, username)
	if err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return domain.LoginResult{}, errs.ErrInvalidUser
	}

	if err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)); err != nil {
		if found && localCfg.MaxFailedAttempts > 0 {
			_, _ = s.repo.IncFailedAttempts(ctx, username, localCfg.MaxFailedAttempts, localCfg.LockoutDuration)
		}
		return domain.LoginResult{}, errs.ErrInvalidUser
	}

	if found {
		_ = s.repo.ClearFailedAttempts(ctx, username)
	}

	return s.postLogin(ctx, u, false)
}

func (s *userService) loginWithProvider(ctx context.Context, providerName string, username, password string) (domain.LoginResult, error) {
	strategy, ok := s.credentialProviders[providerName]
	if !ok {
		return domain.LoginResult{}, errs.ErrProviderNotFound
	}

	// 1. 执行外部认证
	extUser, err := strategy.Authenticate(ctx, username, password)
	if err != nil {
		return domain.LoginResult{}, err
	}
	extUser.Source = domain.Source(providerName)

	// 2. 获取外部身份标识
	id, ok := extUser.GetPrimaryIdentity(providerName)
	if !ok {
		return domain.LoginResult{}, errs.ErrProviderNotFound
	}

	// 3. 查找本地关联用户
	localUser, err := s.repo.FindUserByIdentity(ctx, providerName, id.IdentityKey())
	if err != nil {
		// 4. 执行 JIT 开户
		localUser, err = s.provisionUserByIdentity(ctx, extUser, id)
		if err != nil {
			return domain.LoginResult{}, err
		}
	}

	// 5. 统一执行登录后置逻辑 (包含 MFA 校验和租户初始化)
	return s.postLogin(ctx, localUser, false)
}

func (s *userService) LoginWithExternal(ctx context.Context, ident domain.OidcIdentity) (domain.LoginResult, error) {
	identity := ident.BuildUserIdentity()

	// 1. 查找已绑定的本地用户
	u, err := s.repo.FindUserByIdentity(ctx, identity.Provider, identity.IdentityKey())
	if err == nil {
		return s.postLogin(ctx, u, false)
	}

	// 2. 检查身份源是否允许 JIT
	config, found := s.getOIDCConfig(ctx, ident.Provider)
	if !found || !config.JitEnabled {
		return domain.LoginResult{}, errs.ErrUserNotLinked
	}

	// 3. 执行 JIT 开户
	username := ident.Username
	if username == "" {
		username = ident.ExternalID
	}

	u, err = s.provisionUserByIdentity(ctx, domain.User{
		Username: username,
		Email:    ident.Email,
		Source:   domain.Source(ident.Provider),
	}, identity)
	if err != nil {
		return domain.LoginResult{}, err
	}

	return s.postLogin(ctx, u, false)
}

// postLogin 认证后公共逻辑
func (s *userService) postLogin(ctx context.Context, u domain.User, skipMfa bool) (domain.LoginResult, error) {
	_ = s.repo.UpdateLastLoginAt(ctx, u.ID, time.Now().UnixMilli())

	tenants, err := s.getOrInitTenants(ctx, u.ID, u.Username)
	if err != nil {
		return domain.LoginResult{}, err
	}

	activeTid := s.selectActiveTenant(tenants)
	u, _ = s.repo.FindById(ctxutil.WithTenantID(ctx, activeTid), u.ID)

	res := domain.LoginResult{
		User:             u,
		TenantID:         activeTid,
		Tenants:          tenants,
		MustSelectTenant: len(tenants) > 1,
	}

	if !skipMfa && u.MfaType != "" {
		res.MfaRequired = true
		token := uuid.New().String()
		_ = s.repo.SetMfaToken(ctx, token, u.ID)
		res.MfaToken = token
	}

	return res, nil
}

func (s *userService) getOrInitTenants(ctx context.Context, uid int64, username string) ([]domain.Tenant, error) {
	tenants, err := s.tenantSvc.GetTenantsByUserId(ctx, uid)
	if err != nil {
		return nil, err
	}
	if len(tenants) == 0 {
		tID, err := s.tenantSvc.InitPersonalTenant(ctx, uid, username)
		if err != nil {
			return nil, fmt.Errorf("用户无可用租户空间")
		}
		tenants = []domain.Tenant{{ID: tID}}
	}
	return tenants, nil
}

func (s *userService) selectActiveTenant(tenants []domain.Tenant) int64 {
	for _, t := range tenants {
		if t.ID == ctxutil.SystemTenantID {
			return t.ID
		}
	}
	return tenants[0].ID
}

// provisionUserByIdentity 统一的外部身份 JIT 预供逻辑
func (s *userService) provisionUserByIdentity(ctx context.Context, extUser domain.User, identity domain.UserIdentity) (domain.User, error) {
	// 1. 确保全局用户存在 (不存在则自动 Signup)
	u, err := s.repo.FindByUsername(ctx, extUser.Username)
	var uid int64
	if err != nil {
		uid, err = s.Signup(ctx, extUser)
		if err != nil {
			return domain.User{}, fmt.Errorf("JIT 创建用户失败: %w", err)
		}
	} else {
		uid = u.ID
	}

	// 2. 绑定外部身份标识
	identity.UserID = uid
	if err = s.repo.SaveIdentity(ctx, identity); err != nil {
		return domain.User{}, fmt.Errorf("JIT 绑定身份失败: %w", err)
	}

	// 3. 初始化个人租户空间
	personalTenantID, err := s.tenantSvc.InitPersonalTenant(ctx, uid, extUser.Username)
	if err != nil {
		return domain.User{}, fmt.Errorf("JIT 初始化租户失败: %w", err)
	}

	// 4. 同步更新个人资料 (昵称、头衔等可能随身份源变化)
	newCtx := ctxutil.WithTenantID(ctx, personalTenantID)
	u, err = s.repo.FindById(newCtx, uid)
	if err == nil {
		u.Profile.Nickname = extUser.Profile.Nickname
		u.Profile.JobTitle = extUser.Profile.JobTitle
		_, _ = s.repo.Update(newCtx, u)
	}

	return u, nil
}

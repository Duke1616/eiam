package user

import (
	"context"
	"errors"
	"unicode"

	"github.com/Duke1616/ecmdb/pkg/cryptox"
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	idsource "github.com/Duke1616/eiam/internal/service/identity_source"
	"github.com/Duke1616/eiam/internal/service/tenant"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/errgroup"
)

type IUserService interface {
	Signup(ctx context.Context, u domain.User) (int64, error)
	// Login 认证成功后，同步返回封装好的 LoginResult
	Login(ctx context.Context, provider, username, password string) (domain.LoginResult, error)
	// LoginWithoutPassword 用于 Passkey/OIDC 等已经完成身份验证的场景，直接执行登录后置逻辑
	LoginWithoutPassword(ctx context.Context, uid int64, requireMfa bool) (domain.LoginResult, error)

	// GetById 根据 ID 获取用户信息
	GetById(ctx context.Context, id int64) (domain.User, error)
	// GetByUsername 根据用户名获取用户信息
	GetByUsername(ctx context.Context, username string) (domain.User, error)

	// SwitchTenant 切换当前激活的租户空间
	SwitchTenant(ctx context.Context, uid int64, targetTenantID int64) error
	// Invite 邀请用户进入系统
	Invite(ctx context.Context, username string) error

	// List 分页获取用户列表，支持模糊搜索
	List(ctx context.Context, offset, limit int64, keyword string) ([]domain.User, int64, error)
	// Search 全量搜索用户
	Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.User, error)
	// CountSearch 根据关键词获取符合条件的用户总数
	CountSearch(ctx context.Context, keyword string) (int64, error)
	// Update 更新用户基本资料 (Profile)
	Update(ctx context.Context, u domain.User) (int64, error)
	// UpdatePassword 修改用户本地密码
	UpdatePassword(ctx context.Context, uid int64, oldPassword, newPassword string) error
	// Delete 删除用户
	Delete(ctx context.Context, id int64) error

	// CheckUsersExist 批量检查用户名是否存在
	CheckUsersExist(ctx context.Context, usernames []string) (map[string]bool, error)
	// GetAttachedUsersWithFilter 获取关联角色的用户详情，支持关键词过滤
	GetAttachedUsersWithFilter(ctx context.Context, roleCode string, offset, limit int64, keyword string) ([]domain.User, int64, error)
	// BindIdentity 手动绑定外部身份
	BindIdentity(ctx context.Context, uid int64, identity domain.UserIdentity) error
	// UnbindIdentity 解除外部身份绑定
	UnbindIdentity(ctx context.Context, userID int64, provider, identityID string) error
	// ListIdentitiesByUserID 获取用户的身份绑定列表
	ListIdentitiesByUserID(ctx context.Context, userID int64, provider string) ([]domain.UserIdentity, error)
	// ManageIdentities 批量治理/管理用户的外部身份绑定关系
	ManageIdentities(ctx context.Context, uid int64, identities []domain.UserIdentity) error
	// LoginWithExternal 处理外部身份源登录 (JIT 开户)
	LoginWithExternal(ctx context.Context, ident domain.OidcIdentity, requireMfa bool) (domain.LoginResult, error)
	// GenerateBindToken 生成临时绑定令牌并存入缓存
	GenerateBindToken(ctx context.Context, ident domain.OidcIdentity) (string, error)
	// ConsumeBindToken 消费令牌并执行绑定
	ConsumeBindToken(ctx context.Context, uid int64, token string) error

	SetPasskeyState(ctx context.Context, token string, data webauthn.SessionData) error
	GetPasskeyState(ctx context.Context, token string) (webauthn.SessionData, error)

	// GenerateTOTPSetup 生成 TOTP 密钥和二维码
	GenerateTOTPSetup(ctx context.Context, userID int64) (string, string, error)
	// VerifyAndEnableTOTP 验证并开启 TOTP MFA
	VerifyAndEnableTOTP(ctx context.Context, userID int64, code, secret string) error
	// DisableMFA 关闭 MFA
	DisableMFA(ctx context.Context, userID int64) error
	// VerifyLoginMFA 登录时的 MFA 校验
	VerifyLoginMFA(ctx context.Context, token, code string) (domain.LoginResult, error)
}

var (
	ErrMfaAttemptsExhausted = errors.New("MFA 验证失败次数过多")
	ErrMfaTokenNotFound     = errors.New("MFA 令牌已过期或无效")
)

type userService struct {
	repo                repository.IUserRepository
	tenantSvc           tenant.ITenantService
	idsSvc              idsource.IService
	credentialProviders map[string]domain.CredentialProvider
	cm                  *cryptox.CryptoManager
}

func NewUserService(r repository.IUserRepository, tenantSvc tenant.ITenantService,
	idsSvc idsource.IService, ps []domain.CredentialProvider, cm *cryptox.CryptoManager) IUserService {
	registry := make(map[string]domain.CredentialProvider, len(ps))
	for _, p := range ps {
		registry[p.Name()] = p
	}
	return &userService{
		repo:                r,
		tenantSvc:           tenantSvc,
		idsSvc:              idsSvc,
		credentialProviders: registry,
		cm:                  cm,
	}
}

func (s *userService) SwitchTenant(ctx context.Context, uid int64, targetTenantID int64) error {
	// 直接复用 CheckUserTenantAccess 校验 Membership 合约是否存在
	hasAccess, err := s.tenantSvc.CheckUserTenantAccess(ctx, uid, targetTenantID)
	if err != nil {
		return err
	}

	if !hasAccess {
		return errs.ErrTenantAccessDenied
	}

	return nil
}

func (s *userService) Invite(ctx context.Context, username string) error {
	// 1. 全局查找用户（UserRepository 的 FindByUsername 已经是全局的了，因为它不依赖租户插件）
	u, err := s.repo.FindByUsername(ctx, username)
	if err != nil {
		return err
	}

	// 2. 建立该用户与当前操作租户的 Membership 关系
	return s.tenantSvc.AssignUser(ctx, u.ID)
}

func (s *userService) ListIdentitiesByUserID(ctx context.Context, userID int64, provider string) ([]domain.UserIdentity, error) {
	return s.repo.FindIdentitiesByUserID(ctx, userID, provider)
}

func (s *userService) Signup(ctx context.Context, u domain.User) (int64, error) {
	_, err := s.repo.FindByUsername(ctx, u.Username)
	if err == nil {
		return 0, errs.ErrUserExist
	}

	if u.Source == "" {
		u.Source = domain.SourceLocal
	}

	if u.Status == domain.StatusUnknown {
		u.Status = domain.StatusActive
	}

	if u.Password != "" {
		if err = s.validatePassword(ctx, u.Password); err != nil {
			return 0, err
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			return 0, err
		}
		u.Password = string(hash)
	}
	return s.repo.Create(ctx, u)
}

func (s *userService) UpdatePassword(ctx context.Context, uid int64, oldPassword, newPassword string) error {
	u, err := s.repo.FindById(ctx, uid)
	if err != nil {
		return err
	}

	// 校验旧密码
	if err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(oldPassword)); err != nil {
		return errs.ErrInvalidUser
	}

	// 校验新密码复杂度
	if err = s.validatePassword(ctx, newPassword); err != nil {
		return err
	}

	// 加密新密码
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.Password = string(hash)
	_, err = s.repo.Update(ctx, u)
	return err
}

func (s *userService) GetById(ctx context.Context, id int64) (domain.User, error) {
	return s.repo.FindById(ctx, id)
}

func (s *userService) GetByUsername(ctx context.Context, username string) (domain.User, error) {
	return s.repo.FindByUsername(ctx, username)
}

func (s *userService) List(ctx context.Context, offset, limit int64, keyword string) ([]domain.User, int64, error) {
	var (
		users []domain.User
		total int64
	)
	eg, _ := errgroup.WithContext(ctx)

	// 1. 并发查询用户列表
	eg.Go(func() error {
		var err error
		users, err = s.repo.List(ctx, offset, limit, keyword)
		return err
	})

	// 2. 并发查询总数
	eg.Go(func() error {
		var err error
		total, err = s.repo.Count(ctx, keyword)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

func (s *userService) Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.User, error) {
	if limit <= 0 {
		return []domain.User{}, nil
	}
	return s.repo.Search(ctx, keyword, offset, limit)
}

func (s *userService) CountSearch(ctx context.Context, keyword string) (int64, error) {
	return s.repo.CountSearch(ctx, keyword)
}

func (s *userService) Update(ctx context.Context, u domain.User) (int64, error) {
	return s.repo.Update(ctx, u)
}

func (s *userService) Delete(ctx context.Context, id int64) error {
	return s.repo.Delete(ctx, id)
}

func (s *userService) CheckUsersExist(ctx context.Context, usernames []string) (map[string]bool, error) {
	return s.repo.CheckUsersExist(ctx, usernames)
}

func (s *userService) GetAttachedUsersWithFilter(ctx context.Context, roleCode string, offset, limit int64, keyword string) ([]domain.User, int64, error) {
	return s.repo.GetAttachedUsersWithFilter(ctx, roleCode, offset, limit, keyword)
}

func (s *userService) BindIdentity(ctx context.Context, uid int64, identity domain.UserIdentity) error {
	identity.UserID = uid
	return s.repo.SaveIdentity(ctx, identity)
}

func (s *userService) UnbindIdentity(ctx context.Context, userID int64, provider, identityID string) error {
	return s.repo.DeleteIdentity(ctx, userID, provider, identityID)
}

func (s *userService) ManageIdentities(ctx context.Context, uid int64, identities []domain.UserIdentity) error {
	for _, id := range identities {
		id.UserID = uid
		// 策略：如果标识为空，则解绑；否则绑定/更新
		if id.IdentityKey() == "" {
			if err := s.repo.DeleteIdentity(ctx, uid, id.Provider, id.IdentityKey()); err != nil {
				return err
			}
		} else {
			if err := s.repo.SaveIdentity(ctx, id); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *userService) validatePassword(ctx context.Context, password string) error {
	// 1. 获取本地口令策略（复用统一方法）
	localCfg, found := s.getLocalConfig(ctx)

	// 2. 如果没配置，执行默认最低要求：8 位
	if !found {
		if len(password) < 8 {
			return errs.ErrPasswordWeak
		}
		return nil
	}

	// 3. 执行基础合规性检查（手动规则）
	if len(password) < localCfg.MinLength {
		return errs.ErrPasswordWeak
	}

	var hasDigit, hasUpper, hasLower, hasSymbol bool
	for _, char := range password {
		switch {
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
	}

	if (localCfg.RequireDigit && !hasDigit) ||
		(localCfg.RequireUpper && !hasUpper) ||
		(localCfg.RequireLower && !hasLower) ||
		(localCfg.RequireSymbol && !hasSymbol) {
		return errs.ErrPasswordWeak
	}

	return nil
}

// getLocalConfig 获取已启用的本地口令策略配置
// NOTE: 抽取为独立方法，避免 loginLocal 和 validatePassword 重复查全量身份源列表
// TODO: 后续可增加内存缓存，避免每次都查数据库
func (s *userService) getLocalConfig(ctx context.Context) (domain.LocalConfig, bool) {
	source, err := s.idsSvc.FindEnabled(ctx, domain.LOCAL)
	if err != nil {
		return domain.LocalConfig{}, false
	}

	return source.LocalConfig, true
}

func (s *userService) getOIDCConfig(ctx context.Context, provider string) (domain.OIDCConfig, bool) {
	source, err := s.idsSvc.FindEnabled(ctx, domain.OIDC, provider)
	if err != nil {
		return domain.OIDCConfig{}, false
	}

	return source.OIDCConfig, true
}

func (s *userService) GenerateBindToken(ctx context.Context, ident domain.OidcIdentity) (string, error) {
	token := uuid.New().String()
	if err := s.repo.SetBindState(ctx, token, ident); err != nil {
		return "", err
	}
	return token, nil
}

func (s *userService) ConsumeBindToken(ctx context.Context, uid int64, token string) error {
	ident, err := s.repo.GetBindState(ctx, token)
	if err != nil {
		return err
	}

	return s.BindIdentity(ctx, uid, domain.UserIdentity{
		Provider:   ident.Provider,
		IdentityID: ident.ExternalID,
	})
}

package user

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	idsource "github.com/Duke1616/eiam/internal/service/identity_source"
	"github.com/Duke1616/eiam/internal/service/tenant"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/ecodeclub/ekit/slice"
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
	LoginWithoutPassword(ctx context.Context, uid int64) (domain.LoginResult, error)

	GetById(ctx context.Context, id int64) (domain.User, error)
	GetByUsername(ctx context.Context, username string) (domain.User, error)

	SwitchTenant(ctx context.Context, uid int64, targetTenantID int64) (domain.User, error)
	Invite(ctx context.Context, username string) error

	List(ctx context.Context, offset, limit int64, keyword string) ([]domain.User, int64, error)
	Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.User, error)
	// CountSearch 根据关键词获取符合条件的用户总数
	CountSearch(ctx context.Context, keyword string) (int64, error)
	Update(ctx context.Context, u domain.User) (int64, error)
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
	UnbindIdentity(ctx context.Context, uid int64, provider string) error
	ManageIdentities(ctx context.Context, uid int64, identities []domain.UserIdentity) error
	// LoginWithExternal 处理外部身份源登录 (JIT 开户)
	LoginWithExternal(ctx context.Context, ident domain.OidcIdentity) (domain.LoginResult, error)
	// GenerateBindToken 生成临时绑定令牌并存入缓存
	GenerateBindToken(ctx context.Context, ident domain.OidcIdentity) (string, error)
	// ConsumeBindToken 消费令牌并执行绑定
	ConsumeBindToken(ctx context.Context, uid int64, token string) error

	SetPasskeyState(ctx context.Context, token string, data webauthn.SessionData) error
	GetPasskeyState(ctx context.Context, token string) (webauthn.SessionData, error)
}

type userService struct {
	repo                repository.IUserRepository
	tenantSvc           tenant.ITenantService
	idsSvc              idsource.IService
	credentialProviders map[string]domain.CredentialProvider
}

func NewUserService(r repository.IUserRepository, tenantSvc tenant.ITenantService,
	idsSvc idsource.IService, ps []domain.CredentialProvider) IUserService {
	registry := make(map[string]domain.CredentialProvider, len(ps))
	for _, p := range ps {
		registry[p.Name()] = p
	}
	return &userService{
		repo:                r,
		tenantSvc:           tenantSvc,
		idsSvc:              idsSvc,
		credentialProviders: registry,
	}
}

func (s *userService) Login(ctx context.Context, provider, username, password string) (domain.LoginResult, error) {
	if provider == "local" || provider == "" {
		return s.loginLocal(ctx, username, password)
	}

	return s.loginExternal(ctx, provider, username, password)
}

func (s *userService) loginLocal(ctx context.Context, username, password string) (domain.LoginResult, error) {
	// 1. 获取本地口令策略
	localCfg, found := s.getLocalConfig(ctx)

	// 2. 检查是否已被锁定
	if found && localCfg.MaxFailedAttempts > 0 {
		isLocked, _ := s.repo.IsLocked(ctx, username)
		if isLocked {
			return domain.LoginResult{}, errs.ErrUserLocked
		}
	}

	u, err := s.repo.FindByUsername(ctx, username)
	if err != nil {
		// NOTE: 防时序攻击：即使用户不存在也执行一次 bcrypt 比较，消除响应时间差异
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return domain.LoginResult{}, errs.ErrInvalidUser
	}

	// 3. 校验密码
	if err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)); err != nil {
		// 密码错误，处理失败计数与锁定
		if found && localCfg.MaxFailedAttempts > 0 {
			_, _ = s.repo.IncFailedAttempts(ctx, username, localCfg.MaxFailedAttempts, localCfg.LockoutDuration)
		}
		return domain.LoginResult{}, errs.ErrInvalidUser
	}

	// 4. 登录成功，清除失败计数
	if found {
		_ = s.repo.ClearFailedAttempts(ctx, username)
	}

	return s.postLogin(ctx, u)
}

func (s *userService) LoginWithoutPassword(ctx context.Context, uid int64) (domain.LoginResult, error) {
	u, err := s.repo.FindById(ctx, uid)
	if err != nil {
		return domain.LoginResult{}, err
	}

	return s.postLogin(ctx, u)
}

// dummyHash 用于防时序攻击的哑元哈希值，避免用户不存在时直接跳过 bcrypt 导致响应时间差异
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("anti-timing-attack"), bcrypt.DefaultCost)

func (s *userService) loginExternal(ctx context.Context, providerName string, username, password string) (domain.LoginResult, error) {
	strategy, ok := s.credentialProviders[providerName]
	if !ok {
		return domain.LoginResult{}, errs.ErrProviderNotFound
	}

	extUser, err := strategy.Authenticate(ctx, username, password)
	if err != nil {
		return domain.LoginResult{}, err
	}
	extUser.Source = domain.Source(providerName)

	id, ok := extUser.GetPrimaryIdentity(providerName)
	if !ok {
		return domain.LoginResult{}, errs.ErrProviderNotFound
	}

	// 老用户：进入后续租户路由
	localUser, err := s.repo.FindUserByIdentity(ctx, providerName, id.IdentityKey())
	if err == nil {
		return s.postLogin(ctx, localUser)
	}

	// 新用户：JIT 开荒 → 创建账号 + 绑定身份 + 初始化个人空间
	u, tenantID, err := s.provisionOnLogin(ctx, extUser, id)
	if err != nil {
		return domain.LoginResult{}, err
	}

	// 更新最近登录时间
	_ = s.repo.UpdateLastLoginAt(ctx, u.ID, time.Now().UnixMilli())

	// 新用户只有一个刚建好的空间，直接返回
	return domain.LoginResult{
		User:     u,
		TenantID: tenantID,
		Tenants:  []domain.Tenant{{ID: tenantID}},
	}, nil
}

// postLogin 认证后公共逻辑：查询租户列表并决定路由
func (s *userService) postLogin(ctx context.Context, u domain.User) (domain.LoginResult, error) {
	_ = s.repo.UpdateLastLoginAt(ctx, u.ID, time.Now().UnixMilli())

	// 1. 获取并确保用户至少属于一个租户
	tenants, err := s.getOrInitTenants(ctx, u.ID, u.Username)
	if err != nil {
		return domain.LoginResult{}, err
	}

	// 2. 选取本次登录的激活租户 (母体优先)
	activeTid := s.selectActiveTenant(tenants)

	// 3. 加载租户空间下的完整名片
	u, _ = s.repo.FindById(ctxutil.WithTenantID(ctx, activeTid), u.ID)

	return domain.LoginResult{User: u, TenantID: activeTid, Tenants: tenants}, nil
}

// getOrInitTenants 获取租户列表，若为空则执行延迟初始化 (JIT)
func (s *userService) getOrInitTenants(ctx context.Context, uid int64, username string) ([]domain.Tenant, error) {
	tenants, err := s.tenantSvc.GetTenantsByUserId(ctx, uid)
	if err != nil {
		return nil, err
	}

	if len(tenants) == 0 {
		tID, err := s.tenantSvc.InitPersonalTenant(ctx, uid, username)
		if err != nil {
			return nil, errors.New("用户无可用租户空间")
		}
		tenants = []domain.Tenant{{ID: tID}}
	}

	return tenants, nil
}

// selectActiveTenant 从租户列表中挑选最合适的默认切入点
func (s *userService) selectActiveTenant(tenants []domain.Tenant) int64 {
	// 策略 1：寻找母体/系统租户
	for _, t := range tenants {
		if t.ID == ctxutil.SystemTenantID {
			return t.ID
		}
	}

	// 策略 2：兜底选择首个租户
	return tenants[0].ID
}

// LoginWithExternal 处理外部身份源 (如 OIDC) 的登录请求，包含 JIT 开户逻辑
// 两步走策略：精确匹配身份标识 → JIT 自动开户
func (s *userService) LoginWithExternal(ctx context.Context, ident domain.OidcIdentity) (domain.LoginResult, error) {
	identity := s.buildUserIdentity(ident)

	// 1. 精确匹配：通过 Provider + IdentityID 直接查找
	u, err := s.repo.FindUserByIdentity(ctx, identity.Provider, identity.IdentityKey())
	if err == nil {
		return s.postLogin(ctx, u)
	}

	// 2. 检查该身份源是否允许 JIT 开户
	config, found := s.getOIDCConfig(ctx, ident.Provider)
	if !found || !config.JitEnabled {
		return domain.LoginResult{}, errs.ErrUserNotLinked
	}

	// 3. JIT 开户：身份标识未命中，创建新用户
	u, err = s.provisionJITUser(ctx, ident)
	if err != nil {
		return domain.LoginResult{}, err
	}

	// 4. 绑定外部身份，下次登录直接走第 1 步精确匹配
	identity.UserID = u.ID
	if err = s.repo.SaveIdentity(ctx, identity); err != nil {
		return domain.LoginResult{}, fmt.Errorf("绑定外部身份失败: %w", err)
	}

	return s.postLogin(ctx, u)
}

// provisionJITUser 即时创建用户（Just-In-Time Provisioning）
func (s *userService) provisionJITUser(ctx context.Context, ident domain.OidcIdentity) (domain.User, error) {
	username := ident.Username
	if username == "" {
		username = ident.ExternalID
	}

	u := domain.User{
		Username: username,
		Email:    ident.Email,
		Source:   domain.Source(ident.Provider),
	}

	var err error
	u.ID, err = s.repo.Create(ctx, u)
	if err != nil {
		return domain.User{}, fmt.Errorf("JIT 创建用户失败: %w", err)
	}

	return u, nil
}

// buildUserIdentity 根据外部身份信息动态构建 UserIdentity
func (s *userService) buildUserIdentity(ident domain.OidcIdentity) domain.UserIdentity {
	id := domain.UserIdentity{
		Provider: ident.Provider,
	}

	switch ident.Provider {
	case domain.SourceFeishu.String():
		id.FeishuInfo = domain.FeishuInfo{
			UserID:  getClaimString(ident.RawClaims, "user_id"),
			UnionID: getClaimString(ident.RawClaims, "union_id"),
			OpenID:  getClaimString(ident.RawClaims, "open_id"),
		}
		// NOTE: 飞书的 IdentityID 使用 user_id 作为核心标识
		id.IdentityID = id.FeishuInfo.UserID
	case domain.SourceWechat.String():
		id.WechatInfo = domain.WechatInfo{
			UserID: ident.ExternalID,
		}
		id.IdentityID = ident.ExternalID
	default:
		// NOTE: 通用 OIDC 使用 ExternalID (即 sub claim) 作为统一身份标识
		id.IdentityID = ident.ExternalID
	}

	return id
}

func getClaimString(claims map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, ok := claims[key]; ok {
			if str, ok := val.(string); ok && str != "" {
				return str
			}
		}
	}
	return ""
}
func (s *userService) SwitchTenant(ctx context.Context, uid int64, targetTenantID int64) (domain.User, error) {
	// 直接复用 CheckUserTenantAccess 校验 Membership 合约是否存在
	hasAccess, err := s.tenantSvc.CheckUserTenantAccess(ctx, uid, targetTenantID)
	if err != nil {
		return domain.User{}, err
	}

	if !hasAccess {
		return domain.User{}, errs.ErrTenantAccessDenied
	}

	return s.repo.FindById(ctxutil.WithTenantID(ctx, targetTenantID), uid)
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

func (s *userService) provisionOnLogin(ctx context.Context, ext domain.User, id domain.UserIdentity) (domain.User, int64, error) {
	uid, err := s.ensureGlobalUser(ctx, ext)
	if err != nil {
		return domain.User{}, 0, err
	}

	if err = s.bindGlobalIdentity(ctx, uid, id); err != nil {
		return domain.User{}, 0, err
	}

	personalTenantID, err := s.tenantSvc.InitPersonalTenant(ctx, uid, ext.Username)
	if err != nil {
		return domain.User{}, 0, err
	}

	newCtx := ctxutil.WithTenantID(ctx, personalTenantID)
	u, err := s.repo.FindById(newCtx, uid)
	if err != nil {
		return domain.User{}, 0, err
	}

	u.Profile.Nickname = ext.Profile.Nickname
	u.Profile.JobTitle = ext.Profile.JobTitle
	if _, err = s.repo.Update(newCtx, u); err != nil {
		return domain.User{}, 0, err
	}

	return u, personalTenantID, nil
}

func (s *userService) ensureGlobalUser(ctx context.Context, ext domain.User) (int64, error) {
	u, err := s.repo.FindByUsername(ctx, ext.Username)
	if err == nil {
		return u.ID, nil
	}
	return s.Signup(ctx, ext)
}

func (s *userService) bindGlobalIdentity(ctx context.Context, uid int64, id domain.UserIdentity) error {
	id.UserID = uid
	return s.repo.SaveIdentity(ctx, id)
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

func (s *userService) UnbindIdentity(ctx context.Context, uid int64, provider string) error {
	return s.repo.DeleteIdentity(ctx, uid, provider)
}

func (s *userService) ManageIdentities(ctx context.Context, uid int64, identities []domain.UserIdentity) error {
	for _, id := range identities {
		id.UserID = uid
		// 策略：如果标识为空，则解绑；否则绑定/更新
		if id.IdentityKey() == "" {
			if err := s.repo.DeleteIdentity(ctx, uid, id.Provider); err != nil {
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
	sources, err := s.idsSvc.List(ctx)
	if err != nil {
		return domain.LocalConfig{}, false
	}

	config, found := slice.Find(sources, func(src domain.IdentitySource) bool {
		return src.Type == domain.LOCAL && src.Enabled
	})

	if !found {
		return domain.LocalConfig{}, false
	}

	return config.LocalConfig, true
}

func (s *userService) getOIDCConfig(ctx context.Context, provider string) (domain.OIDCConfig, bool) {
	sources, err := s.idsSvc.List(ctx)
	if err != nil {
		return domain.OIDCConfig{}, false
	}

	config, found := slice.Find(sources, func(src domain.IdentitySource) bool {
		// NOTE: 飞书和微信等提供商在 OIDCConfig 中有具体的 ProviderType
		return src.Type == domain.OIDC && src.Enabled &&
			(string(src.OIDCConfig.ProviderType) == provider || src.Name == provider)
	})

	if !found {
		return domain.OIDCConfig{}, false
	}

	return config.OIDCConfig, true
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

func (s *userService) SetPasskeyState(ctx context.Context, token string, data webauthn.SessionData) error {
	return s.repo.SetPasskeyState(ctx, token, data)
}

func (s *userService) GetPasskeyState(ctx context.Context, token string) (webauthn.SessionData, error) {
	return s.repo.GetPasskeyState(ctx, token)
}

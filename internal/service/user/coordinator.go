package user

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/Duke1616/ecmdb/pkg/cryptox"
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	auditevt "github.com/Duke1616/eiam/internal/event/audit"
	"github.com/Duke1616/eiam/internal/repository"
	idsource "github.com/Duke1616/eiam/internal/service/identity_source"
	"github.com/Duke1616/eiam/internal/service/tenant"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/samber/lo"
)

const MaxMfaAttempts = 5

// IAuthCoordinator 统一认证协调器接口 (Pipeline / Coordinator Pattern)
type IAuthCoordinator interface {
	// Authenticate 执行统一认证流水线 (包含凭证核验、外部关联、MFA决策、租户出单及认证安全审计全闭环)
	Authenticate(ctx context.Context, authType string, payload any) (domain.LoginResult, error)
	// ResolveMfaChallenge 处理两阶段 MFA 挑战应答并衔接完成后续登入出单与认证审计
	ResolveMfaChallenge(ctx context.Context, token, code string) (domain.LoginResult, error)
	// RecordLogout 统一记录用户登出认证安全审计
	RecordLogout(ctx context.Context, uid, tid int64, username string)
}

// authCoordinator 认证流水线引擎核心实现 (纯粹领域编排，由 Wire 统一装配注入)
type authCoordinator struct {
	repo          repository.IUserRepository
	tenantSvc     tenant.ITenantService
	idsSvc        idsource.IService
	cm            *cryptox.CryptoManager
	auditProducer auditevt.IAuditProducer
	strategies    map[string]IAuthStrategy
}

// NewAuthCoordinator 由 Wire 统一依赖注入构建认证流水线协调器
func NewAuthCoordinator(
	repo repository.IUserRepository,
	tenantSvc tenant.ITenantService,
	idsSvc idsource.IService,
	cm *cryptox.CryptoManager,
	auditProducer auditevt.IAuditProducer,
	ps []domain.CredentialProvider,
) IAuthCoordinator {
	registry := lo.SliceToMap(ps, func(p domain.CredentialProvider) (string, domain.CredentialProvider) {
		return p.Name(), p
	})

	coordinator := &authCoordinator{
		repo:          repo,
		tenantSvc:     tenantSvc,
		idsSvc:        idsSvc,
		cm:            cm,
		auditProducer: auditProducer,
		strategies:    make(map[string]IAuthStrategy),
	}

	coordinator.register(newPasswordAuthStrategy(repo, coordinator.getLocalConfig))
	coordinator.register(newLdapAuthStrategy(registry))
	coordinator.register(newOidcAuthStrategy())
	coordinator.register(newPasskeyAuthStrategy(repo))

	return coordinator
}

func (c *authCoordinator) getLocalConfig(ctx context.Context) (domain.LocalConfig, bool) {
	if c.idsSvc == nil {
		return domain.LocalConfig{}, false
	}
	source, err := c.idsSvc.FindEnabled(ctx, domain.LOCAL)
	if err != nil {
		return domain.LocalConfig{}, false
	}
	return source.LocalConfig, true
}

func (c *authCoordinator) getOIDCConfig(ctx context.Context, provider string) (domain.OIDCConfig, bool) {
	if c.idsSvc == nil {
		return domain.OIDCConfig{}, false
	}
	source, err := c.idsSvc.FindEnabled(ctx, domain.OIDC, provider)
	if err != nil {
		return domain.OIDCConfig{}, false
	}
	return source.OIDCConfig, true
}

func (c *authCoordinator) register(strategy IAuthStrategy) {
	c.strategies[strategy.AuthType()] = strategy
}

// Authenticate 执行统一认证流程
func (c *authCoordinator) Authenticate(ctx context.Context, authType string, payload any) (domain.LoginResult, error) {
	if authType == "" {
		authType = domain.LOCAL.String()
	}

	strategy, ok := c.strategies[authType]
	if !ok {
		return domain.LoginResult{}, errs.ErrProviderNotFound
	}

	// 凭据验真
	user, identity, err := strategy.Verify(ctx, payload)
	if err != nil {
		c.recordAuthFailure(ctx, authType, payload, err)
		return domain.LoginResult{}, err
	}

	// 外部身份按需 JIT 预供与关联
	if identity.Provider != "" {
		user, err = c.provisionOrLinkIdentity(ctx, authType, user, identity)
		if err != nil {
			c.recordAuthFailure(ctx, authType, payload, err)
			return domain.LoginResult{}, err
		}
	}

	// MFA 挑战决策
	if strategy.SupportsMFA() && user.MfaType != "" {
		challengeToken := uuid.New().String()
		_ = c.repo.SetMfaToken(ctx, challengeToken, user.ID)
		return domain.LoginResult{
			User:        user,
			AuthType:    authType,
			MfaRequired: true,
			MfaToken:    challengeToken,
		}, nil
	}

	// 租户工作空间装配并出单
	return c.postLoginPipeline(ctx, user, authType)
}

// ResolveMfaChallenge 校验 MFA 挑战验证码并恢复登入流水线
func (c *authCoordinator) ResolveMfaChallenge(ctx context.Context, token, code string) (domain.LoginResult, error) {
	userID, err := c.repo.GetMfaToken(ctx, token)
	if err != nil {
		c.recordAuthFailure(ctx, "mfa", "", errs.ErrMfaTokenNotFound)
		return domain.LoginResult{}, errs.ErrMfaTokenNotFound
	}

	u, err := c.repo.FindById(ctx, userID)
	if err != nil {
		c.recordAuthFailure(ctx, "mfa", "", err)
		return domain.LoginResult{}, err
	}

	if c.cm == nil {
		return domain.LoginResult{}, fmt.Errorf("未配置加密管理器")
	}

	secret, err := c.cm.Decrypt(u.MfaSecret)
	if err != nil {
		return domain.LoginResult{}, fmt.Errorf("解密 MFA 密钥失败: %w", err)
	}

	valid, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if err != nil || !valid {
		c.recordAuthFailure(ctx, "mfa", u.Username, errors.New("MFA 验证码错误"))
		attempts, _ := c.repo.IncMfaAttempts(ctx, token)
		if attempts >= MaxMfaAttempts {
			_ = c.repo.DeleteMfaToken(ctx, token)
			return domain.LoginResult{}, errs.ErrMfaAttemptsExhausted
		}
		remaining := max(0, MaxMfaAttempts-attempts)
		return domain.LoginResult{}, fmt.Errorf("验证码错误 (剩余尝试次数: %d)", remaining)
	}

	_ = c.repo.DeleteMfaToken(ctx, token)
	authType := string(lo.CoalesceOrEmpty(u.Source, domain.SourceLocal))
	return c.postLoginPipeline(ctx, u, authType)
}

// RecordLogout 统一记录用户登出认证安全审计
func (c *authCoordinator) RecordLogout(ctx context.Context, uid, tid int64, username string) {
	if c.auditProducer == nil {
		return
	}
	if tid <= 0 {
		tid = ctxutil.SystemTenantID
	}
	clientIP := ctxutil.GetClientIP(ctx)
	userAgent := ctxutil.GetUserAgent(ctx)

	go func() {
		defer func() { _ = recover() }()
		asyncCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = c.auditProducer.RecordAuth(asyncCtx, domain.AuthLog{
			TenantID:  tid,
			UserID:    uid,
			Username:  username,
			AuthType:  "logout",
			Status:    domain.AuthStatusSuccess,
			ClientIP:  clientIP,
			UserAgent: userAgent,
			Ctime:     time.Now().UnixMilli(),
		})
	}()
}

// recordAuthSuccess 统一异步记录用户登录成功认证安全审计 (由 postLoginPipeline 自动闭环触发)
func (c *authCoordinator) recordAuthSuccess(ctx context.Context, uid, tid int64, username, authType string) {
	if c.auditProducer == nil {
		return
	}
	if tid <= 0 {
		tid = ctxutil.SystemTenantID
	}
	if authType == "" {
		authType = domain.LOCAL.String()
	}
	clientIP := ctxutil.GetClientIP(ctx)
	userAgent := ctxutil.GetUserAgent(ctx)

	go func() {
		defer func() { _ = recover() }()
		asyncCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = c.auditProducer.RecordAuth(asyncCtx, domain.AuthLog{
			TenantID:  tid,
			UserID:    uid,
			Username:  username,
			AuthType:  authType,
			Status:    domain.AuthStatusSuccess,
			ClientIP:  clientIP,
			UserAgent: userAgent,
			Ctime:     time.Now().UnixMilli(),
		})
	}()
}

// recordAuthFailure 统一记录登录认证过程中的安全风控事件，归属记录到系统根租户
func (c *authCoordinator) recordAuthFailure(ctx context.Context, authType string, payload any, err error) {
	if c.auditProducer == nil {
		return
	}
	username := extractUsernameFromPayload(payload)
	failReason := friendlyAuthFailReason(err)
	clientIP := ctxutil.GetClientIP(ctx)
	userAgent := ctxutil.GetUserAgent(ctx)

	_ = c.auditProducer.RecordAuth(ctx, domain.AuthLog{
		TenantID:   ctxutil.SystemTenantID, // 登录错误统一归属系统根租户
		UserID:     0,
		Username:   username,
		AuthType:   authType,
		Status:     domain.AuthStatusFailed,
		FailReason: failReason,
		ClientIP:   clientIP,
		UserAgent:  userAgent,
		Ctime:      time.Now().UnixMilli(),
	})
}

// extractUsernameFromPayload 从强类型入参中提取登录账号名
func extractUsernameFromPayload(payload any) string {
	if payload == nil {
		return ""
	}
	if s, ok := payload.(string); ok {
		return s
	}
	if cred, ok := payload.(PasswordCredential); ok {
		return cred.Username
	}
	if cred, ok := payload.(*PasswordCredential); ok && cred != nil {
		return cred.Username
	}
	val := reflect.ValueOf(payload)
	if val.Kind() == reflect.Pointer {
		val = val.Elem()
	}
	if val.Kind() == reflect.Struct {
		for _, name := range []string{"Username", "Account", "Email"} {
			f := val.FieldByName(name)
			if f.IsValid() && f.Kind() == reflect.String {
				return f.String()
			}
		}
	}
	return ""
}

// friendlyAuthFailReason 将底层哨兵错误转换为清晰易读的安全审计原因
func friendlyAuthFailReason(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, errs.ErrInvalidUser):
		return "账号或密码错误"
	case errors.Is(err, errs.ErrUserLocked):
		return "账号已被锁定"
	case errors.Is(err, errs.ErrUserNotLinked):
		return "外部账号未绑定"
	case errors.Is(err, errs.ErrMfaAttemptsExhausted):
		return "MFA 验证失败次数超限"
	case errors.Is(err, errs.ErrMfaTokenNotFound):
		return "MFA 会话已过期"
	default:
		return err.Error()
	}
}

// provisionOrLinkIdentity 统一处理外部身份源用户关联与 JIT 预供建档
func (c *authCoordinator) provisionOrLinkIdentity(ctx context.Context, provider string, extUser domain.User, identity domain.UserIdentity) (domain.User, error) {
	localUser, err := c.repo.FindUserByIdentity(ctx, provider, identity.IdentityKey())
	if err == nil {
		return localUser, nil
	}

	// 若为 OIDC 单点登录，检查 JIT 启用配置
	if provider == domain.OIDC.String() {
		config, found := c.getOIDCConfig(ctx, identity.Provider)
		if !found || !config.JitEnabled {
			return domain.User{}, errs.ErrUserNotLinked
		}
	}

	return c.provisionUserByIdentity(ctx, extUser, identity)
}

// provisionUserByIdentity 统一的外部身份 JIT 预供逻辑
func (c *authCoordinator) provisionUserByIdentity(ctx context.Context, extUser domain.User, identity domain.UserIdentity) (domain.User, error) {
	u, err := c.repo.FindByUsername(ctx, extUser.Username)
	var uid int64
	if err != nil {
		if extUser.Source == "" {
			extUser.Source = domain.Source(identity.Provider)
		}
		if extUser.Status == domain.StatusUnknown {
			extUser.Status = domain.StatusActive
		}
		uid, err = c.repo.Create(ctx, extUser)
		if err != nil {
			return domain.User{}, fmt.Errorf("JIT 创建用户失败: %w", err)
		}
	} else {
		uid = u.ID
	}

	identity.UserID = uid
	if err = c.repo.SaveIdentity(ctx, identity); err != nil {
		return domain.User{}, fmt.Errorf("JIT 绑定身份失败: %w", err)
	}

	personalTenantID, err := c.tenantSvc.InitPersonalTenant(ctx, uid, extUser.Username)
	if err != nil {
		return domain.User{}, fmt.Errorf("JIT 初始化租户失败: %w", err)
	}

	newCtx := ctxutil.WithTenantID(ctx, personalTenantID)
	u, err = c.repo.FindById(newCtx, uid)
	if err == nil {
		u.Profile.Nickname = extUser.Profile.Nickname
		u.Profile.JobTitle = extUser.Profile.JobTitle
		_, _ = c.repo.Update(newCtx, u)
	}

	return u, nil
}

// postLoginPipeline 登录成功后的租户初始化与结果构建
func (c *authCoordinator) postLoginPipeline(ctx context.Context, u domain.User, authType string) (domain.LoginResult, error) {
	_ = c.repo.UpdateLastLoginAt(ctx, u.ID, time.Now().UnixMilli())

	tenants, err := c.getOrInitTenants(ctx, u.ID, u.Username)
	if err != nil {
		return domain.LoginResult{}, err
	}

	var activeTid int64
	mustSelectTenant := len(tenants) > 1
	if !mustSelectTenant && len(tenants) == 1 {
		activeTid = tenants[0].ID
		u, _ = c.repo.FindById(ctxutil.WithTenantID(ctx, activeTid), u.ID)
	}

	auditTid := activeTid
	if auditTid <= 0 && len(tenants) > 0 {
		auditTid = tenants[0].ID
	}
	c.recordAuthSuccess(ctx, u.ID, auditTid, u.Username, authType)

	return domain.LoginResult{
		User:             u,
		TenantID:         activeTid,
		Tenants:          tenants,
		AuthType:         authType,
		MustSelectTenant: mustSelectTenant,
	}, nil
}

func (c *authCoordinator) getOrInitTenants(ctx context.Context, uid int64, username string) ([]domain.Tenant, error) {
	tenants, err := c.tenantSvc.GetTenantsByUserId(ctx, uid)
	if err != nil {
		return nil, err
	}
	if len(tenants) == 0 {
		tID, err := c.tenantSvc.InitPersonalTenant(ctx, uid, username)
		if err != nil {
			return nil, fmt.Errorf("用户无可用租户空间")
		}
		tenants = []domain.Tenant{{ID: tID}}
	}
	return tenants, nil
}

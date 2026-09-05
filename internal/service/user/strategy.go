package user

import (
	"context"
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// dummyHash 用于用户不存在时对齐 bcrypt 校验耗时，防时序攻击
var dummyHash = []byte("$2a$10$kXMFk5pN5KlEOpBmkVUny.2i28ILDBO0MOu1tw1qGKSqR9QAkLX/O")

// PasswordCredential 通用账密凭据载荷
type PasswordCredential struct {
	Username string
	Password string
}

// extractPayload 从 any 载荷中提取值，兼容指针与值类型
func extractPayload[T any](payload any) (T, bool) {
	switch v := payload.(type) {
	case T:
		return v, true
	case *T:
		if v != nil {
			return *v, true
		}
	}
	var zero T
	return zero, false
}

// IAuthStrategy 统一身份凭据验真策略接口 (Strategy Pattern)
type IAuthStrategy interface {
	// AuthType 声明认证源类型: local, ldap, oidc, passkey 等
	AuthType() string
	// SupportsMFA 声明该认证源是否支持触发二次 MFA
	SupportsMFA() bool
	// Verify 验证具体凭据并返回对应用户模型与外部身份元数据
	Verify(ctx context.Context, payload any) (domain.User, domain.UserIdentity, error)
}

// passwordAuthStrategy 本地账号密码验真策略
type passwordAuthStrategy struct {
	repo        repository.IUserRepository
	localCfgFn func(ctx context.Context) (domain.LocalConfig, bool)
}

func newPasswordAuthStrategy(repo repository.IUserRepository, localCfgFn func(ctx context.Context) (domain.LocalConfig, bool)) IAuthStrategy {
	return &passwordAuthStrategy{
		repo:        repo,
		localCfgFn: localCfgFn,
	}
}

func (s *passwordAuthStrategy) AuthType() string {
	return domain.LOCAL.String()
}

func (s *passwordAuthStrategy) SupportsMFA() bool {
	return true
}

func (s *passwordAuthStrategy) Verify(ctx context.Context, payload any) (domain.User, domain.UserIdentity, error) {
	cred, ok := extractPayload[PasswordCredential](payload)
	if !ok {
		return domain.User{}, domain.UserIdentity{}, fmt.Errorf("非法账密凭据载荷")
	}

	var localCfg domain.LocalConfig
	var found bool
	if s.localCfgFn != nil {
		localCfg, found = s.localCfgFn(ctx)
	}

	if found && localCfg.MaxFailedAttempts > 0 {
		isLocked, _ := s.repo.IsLocked(ctx, cred.Username)
		if isLocked {
			return domain.User{}, domain.UserIdentity{}, errs.ErrUserLocked
		}
	}

	u, err := s.repo.FindByUsername(ctx, cred.Username)
	if err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(cred.Password))
		return domain.User{}, domain.UserIdentity{}, errs.ErrInvalidUser
	}

	if err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(cred.Password)); err != nil {
		if found && localCfg.MaxFailedAttempts > 0 {
			_, _ = s.repo.IncFailedAttempts(ctx, cred.Username, localCfg.MaxFailedAttempts, localCfg.LockoutDuration)
		}
		return domain.User{}, domain.UserIdentity{}, errs.ErrInvalidUser
	}

	if found {
		_ = s.repo.ClearFailedAttempts(ctx, cred.Username)
	}

	return u, domain.UserIdentity{}, nil
}

// ldapAuthStrategy 动态外部目录身份源验真策略
type ldapAuthStrategy struct {
	providers map[string]domain.CredentialProvider
}

func newLdapAuthStrategy(providers map[string]domain.CredentialProvider) IAuthStrategy {
	return &ldapAuthStrategy{providers: providers}
}

func (s *ldapAuthStrategy) AuthType() string {
	return domain.LDAP.String()
}

func (s *ldapAuthStrategy) SupportsMFA() bool {
	return true
}

func (s *ldapAuthStrategy) Verify(ctx context.Context, payload any) (domain.User, domain.UserIdentity, error) {
	cred, ok := extractPayload[PasswordCredential](payload)
	if !ok {
		return domain.User{}, domain.UserIdentity{}, fmt.Errorf("非法 LDAP 凭据载荷")
	}

	provider, ok := s.providers[domain.LDAP.String()]
	if !ok {
		return domain.User{}, domain.UserIdentity{}, errs.ErrProviderNotFound
	}

	extUser, err := provider.Authenticate(ctx, cred.Username, cred.Password)
	if err != nil {
		return domain.User{}, domain.UserIdentity{}, err
	}
	extUser.Source = domain.Source(domain.LDAP.String())

	id, ok := extUser.GetPrimaryIdentity(domain.LDAP.String())
	if !ok {
		return domain.User{}, domain.UserIdentity{}, errs.ErrProviderNotFound
	}

	return extUser, id, nil
}

// oidcAuthStrategy OIDC 单点登录外部身份验真策略
type oidcAuthStrategy struct{}

func newOidcAuthStrategy() IAuthStrategy {
	return &oidcAuthStrategy{}
}

func (s *oidcAuthStrategy) AuthType() string {
	return domain.OIDC.String()
}

func (s *oidcAuthStrategy) SupportsMFA() bool {
	return true
}

func (s *oidcAuthStrategy) Verify(ctx context.Context, payload any) (domain.User, domain.UserIdentity, error) {
	ident, ok := extractPayload[domain.OidcIdentity](payload)
	if !ok {
		return domain.User{}, domain.UserIdentity{}, fmt.Errorf("非法 OIDC 身份凭据")
	}

	identity := ident.BuildUserIdentity()
	username := ident.Username
	if username == "" {
		username = ident.ExternalID
	}

	user := domain.User{
		Username: username,
		Email:    ident.Email,
		Source:   domain.Source(ident.Provider),
	}

	return user, identity, nil
}

// passkeyAuthStrategy Passkey 免密验真策略
type passkeyAuthStrategy struct {
	repo repository.IUserRepository
}

func newPasskeyAuthStrategy(repo repository.IUserRepository) IAuthStrategy {
	return &passkeyAuthStrategy{repo: repo}
}

func (s *passkeyAuthStrategy) AuthType() string {
	return domain.PASSKEY.String()
}

func (s *passkeyAuthStrategy) SupportsMFA() bool {
	return false
}

func (s *passkeyAuthStrategy) Verify(ctx context.Context, payload any) (domain.User, domain.UserIdentity, error) {
	uid, ok := extractPayload[int64](payload)
	if !ok {
		return domain.User{}, domain.UserIdentity{}, fmt.Errorf("非法 Passkey 凭据载荷")
	}

	u, err := s.repo.FindById(ctx, uid)
	if err != nil {
		return domain.User{}, domain.UserIdentity{}, err
	}

	return u, domain.UserIdentity{}, nil
}

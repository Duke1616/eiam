package identity_source

import (
	"context"
	"fmt"

	"github.com/Duke1616/ecmdb/pkg/cryptox"
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/pkg/ldapx"
	"github.com/ecodeclub/ekit/slice"
	"github.com/google/uuid"
	"github.com/gotomicro/ego/core/elog"
)

type IService interface {
	// Save 保存身份源配置，对敏感字段进行加密
	Save(ctx context.Context, source domain.IdentitySource) (int64, error)

	// List 获取所有身份源列表
	List(ctx context.Context) ([]domain.IdentitySource, error)

	// GetByID 根据 ID 获取身份源详情
	GetByID(ctx context.Context, id int64) (domain.IdentitySource, error)

	// Delete 删除指定的身份源
	Delete(ctx context.Context, id int64) error

	// GetAuthURL 根据 provider_type 获取 OIDC 授权跳转地址
	GetAuthURL(ctx context.Context, providerType string) (string, error)

	// VerifyOIDC 校验回调并返回外部身份信息 (包含 State 校验)
	VerifyOIDC(ctx context.Context, state, code string) (domain.OidcIdentity, error)

	// GetEnabledProviderTypes 获取所有已启用的登录提供商类型（用于登录页展示按钮/标签）
	GetEnabledProviderTypes(ctx context.Context) ([]string, error)

	// TestConnection 测试 LDAP 连通性
	TestConnection(ctx context.Context, source domain.IdentitySource) error

	// ToggleEnabled 切换身份源启用状态
	ToggleEnabled(ctx context.Context, id int64) error

	// GetEnabledByType 获取指定类型且已启用的身份源列表
	GetEnabledByType(ctx context.Context, sourceType domain.IdentitySourceType) ([]domain.IdentitySource, error)

	// FindEnabled 获取精准匹配且已启用的身份源
	// 对于 LOCAL/LDAP/PASSKEY，取该类型的唯一项
	// 对于 OIDC，需传入具体 provider 标识 (如 "feishu")
	FindEnabled(ctx context.Context, sourceType domain.IdentitySourceType, provider ...string) (domain.IdentitySource, error)
}

type service struct {
	repo    repository.IIdentitySourceRepository
	oidcSvc OidcService
	cm      *cryptox.CryptoManager
	logger  *elog.Component
}

func NewService(repo repository.IIdentitySourceRepository, oidcSvc OidcService, cm *cryptox.CryptoManager) IService {
	return &service{
		repo:    repo,
		oidcSvc: oidcSvc,
		cm:      cm,
		logger:  elog.DefaultLogger,
	}
}

// Save 保存身份源配置，对敏感字段进行加密
func (s *service) Save(ctx context.Context, source domain.IdentitySource) (int64, error) {
	// 仅加密非空且非占位符的敏感字段
	if err := s.encryptSecrets(&source); err != nil {
		return 0, err
	}

	return s.repo.Save(ctx, source)
}

func (s *service) encryptSecrets(source *domain.IdentitySource) error {
	switch source.Type {
	case domain.LDAP:
		if source.LDAPConfig.BindPassword != "" && source.LDAPConfig.BindPassword != "******" {
			encrypted, err := s.cm.Encrypt(source.LDAPConfig.BindPassword)
			if err != nil {
				return fmt.Errorf("加密 LDAP 密码失败: %w", err)
			}
			source.LDAPConfig.BindPassword = encrypted
		}
	case domain.OIDC:
		if source.OIDCConfig.ClientSecret != "" && source.OIDCConfig.ClientSecret != "******" {
			encrypted, err := s.cm.Encrypt(source.OIDCConfig.ClientSecret)
			if err != nil {
				return fmt.Errorf("加密 OIDC 密钥失败: %w", err)
			}
			source.OIDCConfig.ClientSecret = encrypted
		}
	}
	return nil
}

// List 获取当前租户下的所有身份源列表
func (s *service) List(ctx context.Context) ([]domain.IdentitySource, error) {
	sources, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}

	for i := range sources {
		decrypted, err := s.decryptSource(sources[i])
		if err != nil {
			s.logger.Warn("身份源配置解密失败", elog.Int64("id", sources[i].ID), elog.FieldErr(err))
			continue
		}
		sources[i] = decrypted
	}

	return sources, nil
}

// GetByID 根据 ID 获取身份源详情
func (s *service) GetByID(ctx context.Context, id int64) (domain.IdentitySource, error) {
	source, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return domain.IdentitySource{}, err
	}

	return s.decryptSource(source)
}

// Delete 删除指定的身份源
func (s *service) Delete(ctx context.Context, id int64) error {
	return s.repo.Delete(ctx, id)
}

func (s *service) GetAuthURL(ctx context.Context, providerType string) (string, error) {
	// 1. 查找当前租户下匹配 provider_type 的启用 OIDC 身份源
	source, err := s.FindEnabled(ctx, domain.OIDC, providerType)
	if err != nil {
		s.logger.Error("[OIDC] 查找启用的 OIDC 身份源失败", elog.String("provider_type", providerType), elog.FieldErr(err))
		return "", err
	}

	s.logger.Info("[OIDC] 找到身份源",
		elog.Int64("source_id", source.ID),
		elog.String("name", source.Name),
		elog.String("redirect_uri", source.OIDCConfig.RedirectURI),
		elog.String("auth_url", source.OIDCConfig.AuthURL),
		elog.String("token_url", source.OIDCConfig.TokenURL),
		elog.String("user_info_url", source.OIDCConfig.UserInfoURL),
	)

	// 2. 解密敏感配置
	source, err = s.decryptSource(source)
	if err != nil {
		s.logger.Error("[OIDC] 解密身份源配置失败", elog.FieldErr(err))
		return "", err
	}

	// 3. 生成 State 和 Nonce
	state := uuid.New().String()
	nonce := uuid.New().String()
	if err = s.repo.SaveState(ctx, state, source.ID, nonce); err != nil {
		s.logger.Error("[OIDC] 保存 State 到 Redis 失败", elog.FieldErr(err))
		return "", err
	}

	// 4. 调用协议专家生成 URL (带 nonce)
	return s.oidcSvc.AuthURL(ctx, source.OIDCConfig, state, nonce)
}

func (s *service) VerifyOIDC(ctx context.Context, state, code string) (domain.OidcIdentity, error) {
	// 1. 校验并获取 SourceID 和 Nonce (Redis，一次性校验)
	sourceID, nonce, err := s.repo.GetState(ctx, state)
	if err != nil {
		s.logger.Error("[OIDC] State 校验失败（可能已过期或重复使用）", elog.String("state", state), elog.FieldErr(err))
		return domain.OidcIdentity{}, fmt.Errorf("state 校验失败: %w", err)
	}

	s.logger.Info("[OIDC] State 校验通过", elog.Int64("source_id", sourceID))

	// 2. 获取配置
	source, err := s.repo.GetByID(ctx, sourceID)
	if err != nil {
		s.logger.Error("[OIDC] 获取身份源配置失败", elog.Int64("source_id", sourceID), elog.FieldErr(err))
		return domain.OidcIdentity{}, err
	}
	source, err = s.decryptSource(source)
	if err != nil {
		s.logger.Error("[OIDC] 解密身份源配置失败", elog.FieldErr(err))
		return domain.OidcIdentity{}, err
	}

	s.logger.Info("[OIDC] 开始 Code 交换", elog.String("token_url", source.OIDCConfig.TokenURL))

	// 3. 调用协议专家完成 Code 交换与校验 (带 nonce 校验)
	return s.oidcSvc.Verify(ctx, source, code, nonce)
}

func (s *service) GetEnabledProviderTypes(ctx context.Context) ([]string, error) {
	return s.repo.GetEnabledProviderTypes(ctx)
}

func (s *service) FindEnabled(ctx context.Context, sourceType domain.IdentitySourceType, provider ...string) (domain.IdentitySource, error) {
	sources, err := s.GetEnabledByType(ctx, sourceType)
	if err != nil {
		return domain.IdentitySource{}, err
	}

	if len(sources) == 0 {
		return domain.IdentitySource{}, fmt.Errorf("未找到类型为 %s 的启用身份源", sourceType)
	}

	// 1. 对于单例类型，直接返回第一个（逻辑上应只有一个）
	if sourceType != domain.OIDC {
		return sources[0], nil
	}

	// 2. 对于 OIDC 类型，根据 provider 匹配
	if len(provider) == 0 {
		return domain.IdentitySource{}, fmt.Errorf("获取 OIDC 配置必须提供 provider 标识")
	}

	target := provider[0]
	config, found := slice.Find(sources, func(src domain.IdentitySource) bool {
		return string(src.OIDCConfig.ProviderType) == target || src.Name == target
	})

	if !found {
		return domain.IdentitySource{}, fmt.Errorf("未找到 provider 为 %s 的启用 OIDC 身份源", target)
	}

	return config, nil
}

// TestConnection 测试 LDAP 连通性
func (s *service) TestConnection(ctx context.Context, source domain.IdentitySource) error {
	password := source.LDAPConfig.BindPassword

	// 如果未提供密码且 ID 存在，尝试从数据库获取原有密码
	if password == "" && source.ID > 0 {
		old, err := s.repo.GetByID(ctx, source.ID)
		if err == nil {
			password = old.LDAPConfig.BindPassword
		}
	}

	if password != "" {
		decrypted, err := s.cm.Decrypt(password)
		if err == nil {
			password = decrypted
		}
	}

	cfg := source.LDAPConfig
	client := ldapx.NewClient(ldapx.Config{
		URL:          cfg.URL,
		BaseDN:       cfg.BaseDN,
		BindDN:       cfg.BindDN,
		BindPassword: password,
	})

	return client.CheckConnect()
}

func (s *service) ToggleEnabled(ctx context.Context, id int64) error {
	return s.repo.ToggleEnabled(ctx, id)
}

func (s *service) GetEnabledByType(ctx context.Context, sourceType domain.IdentitySourceType) ([]domain.IdentitySource, error) {
	sources, err := s.repo.GetEnabledByType(ctx, sourceType)
	if err != nil {
		return nil, err
	}

	for i := range sources {
		decrypted, err := s.decryptSource(sources[i])
		if err != nil {
			s.logger.Warn("身份源配置解密失败", elog.Int64("id", sources[i].ID), elog.FieldErr(err))
			continue
		}
		sources[i] = decrypted
	}

	return sources, nil
}

func (s *service) decryptSource(source domain.IdentitySource) (domain.IdentitySource, error) {
	switch source.Type {
	case domain.LDAP:
		if source.LDAPConfig.BindPassword == "" {
			return source, nil
		}
		password, err := s.cm.Decrypt(source.LDAPConfig.BindPassword)
		if err != nil {
			return domain.IdentitySource{}, fmt.Errorf("解密 LDAP 密码失败: %w", err)
		}
		source.LDAPConfig.BindPassword = password
	case domain.OIDC:
		if source.OIDCConfig.ClientSecret == "" {
			return source, nil
		}
		secret, err := s.cm.Decrypt(source.OIDCConfig.ClientSecret)
		if err != nil {
			return domain.IdentitySource{}, fmt.Errorf("解密 OIDC 密钥失败: %w", err)
		}
		source.OIDCConfig.ClientSecret = secret
	}
	return source, nil
}

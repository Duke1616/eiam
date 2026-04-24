package identity_source

import (
	"context"
	"fmt"

	"github.com/Duke1616/ecmdb/pkg/cryptox"
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/user/ldapx"
)

type service struct {
	repo repository.IIdentitySourceRepository
	cm   *cryptox.CryptoManager
}

func NewService(repo repository.IIdentitySourceRepository, cm *cryptox.CryptoManager) IService {
	return &service{
		repo: repo,
		cm:   cm,
	}
}

// Save 保存身份源配置，对敏感字段进行加密
func (s *service) Save(ctx context.Context, source domain.IdentitySource) (int64, error) {
	if source.Type == domain.LDAP && source.LDAPConfig.BindPassword != "" {
		encrypted, err := s.cm.Encrypt(source.LDAPConfig.BindPassword)
		if err != nil {
			return 0, fmt.Errorf("加密密码失败: %w", err)
		}
		source.LDAPConfig.BindPassword = encrypted
	}

	return s.repo.Save(ctx, source)
}

// List 获取当前租户下的所有身份源列表
func (s *service) List(ctx context.Context) ([]domain.IdentitySource, error) {
	return s.repo.List(ctx)
}

// GetByID 根据 ID 获取身份源详情
func (s *service) GetByID(ctx context.Context, id int64) (domain.IdentitySource, error) {
	return s.repo.GetByID(ctx, id)
}

// Delete 删除指定的身份源
func (s *service) Delete(ctx context.Context, id int64) error {
	return s.repo.Delete(ctx, id)
}

// TestConnection 测试 LDAP 连通性
func (s *service) TestConnection(ctx context.Context, source domain.IdentitySource) error {
	cfg := source.LDAPConfig
	password, err := s.cm.Decrypt(cfg.BindPassword)
	if err != nil {
		return fmt.Errorf("解密密码失败: %w", err)
	}

	ldapConf := ldapx.Config{
		Url:                  cfg.URL,
		BaseDN:               cfg.BaseDN,
		BindDN:               cfg.BindDN,
		BindPassword:         password,
		UserFilter:           cfg.UserFilter,
		SyncUserFilter:       cfg.SyncUserFilter,
		UsernameAttribute:    cfg.UsernameAttribute,
		MailAttribute:        cfg.MailAttribute,
		DisplayNameAttribute: cfg.DisplayNameAttribute,
	}

	provider := ldapx.NewLdap(ldapConf)
	return provider.CheckConnect()
}

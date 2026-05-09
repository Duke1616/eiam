package ldap

import (
	"context"
	"errors"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/cache"
	idsource "github.com/Duke1616/eiam/internal/service/identity_source"
	"github.com/Duke1616/eiam/internal/service/tenant"
	"github.com/Duke1616/eiam/internal/service/user/ldapx"
)

type LdapService interface {
	Login(ctx context.Context, username, password string) (domain.User, error)
	SearchCacheUserWithPager(ctx context.Context, tid int64, keywords string, offset, limit int) ([]domain.User, int, error)
	RefreshCacheUserWithPager(ctx context.Context, tid int64) error
	Sync(ctx context.Context, tid int64, users []domain.User) error
}

type ldapService struct {
	repo      repository.IUserRepository
	tenantSvc tenant.ITenantService
	idsSvc    idsource.IService
	cache     cache.RedisearchLdapUserCache
}

func NewLdapService(repo repository.IUserRepository, tenantSvc tenant.ITenantService,
	idsSvc idsource.IService, cache cache.RedisearchLdapUserCache) LdapService {
	return &ldapService{
		repo:      repo,
		tenantSvc: tenantSvc,
		idsSvc:    idsSvc,
		cache:     cache,
	}
}

func (l *ldapService) Sync(ctx context.Context, tid int64, users []domain.User) error {
	now := time.Now().UnixMilli()
	usernames := make([]string, 0, len(users))
	for i := range users {
		users[i].Source = domain.SourceLdap
		users[i].Status = domain.StatusActive
		users[i].Ctime = now
		users[i].Utime = now
		usernames = append(usernames, users[i].Username)
	}

	// 1. 批量持久化用户
	if err := l.repo.BatchUpsert(ctx, users); err != nil {
		return err
	}

	// 2. 重新获取数据库生成的 ID（用于后续租户初始化）
	savedUsers, err := l.repo.FindUsersByUsernames(ctx, usernames)
	if err != nil {
		return err
	}

	// 3. 为用户初始化个人租户空间（Batch 批量处理）
	return l.tenantSvc.BatchInitPersonalTenant(ctx, savedUsers)
}

func (l *ldapService) SearchCacheUserWithPager(ctx context.Context, tid int64, keywords string,
	offset, limit int) ([]domain.User, int, error) {
	return l.cache.Query(ctx, tid, keywords, offset, limit)
}

func (l *ldapService) RefreshCacheUserWithPager(ctx context.Context, tid int64) error {
	config, ok := l.getLDAPConfig(ctx)
	if !ok {
		return errors.New("未找到启用的 LDAP 身份源配置")
	}

	provider := ldapx.NewLdap(l.toLdapxConfig(config))
	ldapUsers, err := provider.SearchUserWithPaging(ctx)
	if err != nil {
		return err
	}

	return l.cache.Document(ctx, tid, ldapUsers)
}

// Login LDAP 登录
func (l *ldapService) Login(ctx context.Context, username, password string) (domain.User, error) {
	config, ok := l.getLDAPConfig(ctx)
	if !ok {
		return domain.User{}, errors.New("未找到启用的 LDAP 身份源配置")
	}

	provider := ldapx.NewLdap(l.toLdapxConfig(config))
	return provider.Authenticate(ctx, username, password)
}

func (l *ldapService) getLDAPConfig(ctx context.Context) (domain.LDAPConfig, bool) {
	source, err := l.idsSvc.FindEnabled(ctx, domain.LDAP)
	if err != nil {
		return domain.LDAPConfig{}, false
	}

	return source.LDAPConfig, true
}

func (l *ldapService) toLdapxConfig(cfg domain.LDAPConfig) ldapx.Config {
	return ldapx.Config{
		Url:                  cfg.URL,
		BaseDN:               cfg.BaseDN,
		BindDN:               cfg.BindDN,
		BindPassword:         cfg.BindPassword,
		UsernameAttribute:    cfg.UsernameAttribute,
		MailAttribute:        cfg.MailAttribute,
		DisplayNameAttribute: cfg.DisplayNameAttribute,
		TitleAttribute:       cfg.TitleAttribute,
		UserFilter:           cfg.UserFilter,
		SyncUserFilter:       cfg.SyncUserFilter,
	}
}

package user

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/service/tenant"
	"github.com/Duke1616/eiam/internal/service/user/ldapx"
)

type LdapService interface {
	Login(ctx context.Context, username, password string) (domain.User, error)
	SearchCacheUserWithPager(ctx context.Context, keywords string, offset, limit int) ([]domain.User, int, error)
	RefreshCacheUserWithPager(ctx context.Context) error
	Sync(ctx context.Context, users []domain.User) error
}

type ldapService struct {
	repo      repository.IUserRepository
	tenantSvc tenant.ITenantService
	ldap      ldapx.LdapProvider
	cache     cache.RedisearchLdapUserCache
}

func NewLdapService(repo repository.IUserRepository, tenantSvc tenant.ITenantService,
	conf ldapx.Config, cache cache.RedisearchLdapUserCache) LdapService {
	return &ldapService{
		repo:      repo,
		tenantSvc: tenantSvc,
		ldap:      ldapx.NewLdap(conf),
		cache:     cache,
	}
}

func (l *ldapService) Sync(ctx context.Context, users []domain.User) error {
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

func (l *ldapService) SearchCacheUserWithPager(ctx context.Context, keywords string,
	offset, limit int) ([]domain.User, int, error) {
	return l.cache.Query(ctx, keywords, offset, limit)
}

func (l *ldapService) RefreshCacheUserWithPager(ctx context.Context) error {
	ldapUsers, err := l.ldap.SearchUserWithPaging(ctx)
	if err != nil {
		return err
	}

	return l.cache.Document(ctx, ldapUsers)
}

// Login LDAP 登录
func (l *ldapService) Login(ctx context.Context, username, password string) (domain.User, error) {
	return l.ldap.Authenticate(ctx, username, password)
}

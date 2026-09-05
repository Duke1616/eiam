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
)

// ILdapService LDAP 业务逻辑接口
type ILdapService interface {
	// SearchCacheUserWithPager 基于 RediSearch 缓存分页检索 LDAP 用户
	SearchCacheUserWithPager(ctx context.Context, tid int64, keywords string, offset, limit int) ([]domain.User, int, error)

	// RefreshCacheUserWithPager 从远端 LDAP 服务器拉取用户数据并刷新 RediSearch 缓存
	RefreshCacheUserWithPager(ctx context.Context, tid int64) error

	// Sync 批量持久化 LDAP 用户，初始化个人空间并绑定当前租户成员关系
	Sync(ctx context.Context, tid int64, users []domain.User) error
}

type ldapService struct {
	repo      repository.IUserRepository
	tenantSvc tenant.ITenantService
	idsSvc    idsource.IService
	cache     cache.RedisearchLdapUserCache
}

// NewLdapService 创建 LDAP 业务服务实例
func NewLdapService(repo repository.IUserRepository, tenantSvc tenant.ITenantService,
	idsSvc idsource.IService, cache cache.RedisearchLdapUserCache) ILdapService {
	return &ldapService{
		repo:      repo,
		tenantSvc: tenantSvc,
		idsSvc:    idsSvc,
		cache:     cache,
	}
}

// Sync 批量持久化 LDAP 用户至系统，初始化个人空间并绑定当前租户成员关系
func (l *ldapService) Sync(ctx context.Context, tid int64, users []domain.User) error {
	if len(users) == 0 {
		return nil
	}

	now := time.Now().UnixMilli()
	usernames := make([]string, 0, len(users))
	for i := range users {
		users[i].Source = domain.SourceLdap
		users[i].Status = domain.StatusActive
		users[i].Ctime = now
		users[i].Utime = now
		usernames = append(usernames, users[i].Username)
	}

	// 批量持久化用户基础信息
	if err := l.repo.BatchUpsert(ctx, users); err != nil {
		return err
	}

	// 查询落库后的用户实体获取系统生成 ID
	savedUsers, err := l.repo.FindUsersByUsernames(ctx, usernames)
	if err != nil {
		return err
	}

	// 批量初始化个人租户空间
	if err := l.tenantSvc.BatchInitPersonalTenant(ctx, savedUsers); err != nil {
		return err
	}

	if tid <= 0 {
		return nil
	}

	userIDs := make([]int64, 0, len(savedUsers))
	for _, u := range savedUsers {
		userIDs = append(userIDs, u.ID)
	}
	return l.tenantSvc.BatchAssignTenants(ctx, userIDs, []int64{tid})
}

// SearchCacheUserWithPager 从 RediSearch 索引中按关键字模糊分页查询 LDAP 用户
func (l *ldapService) SearchCacheUserWithPager(ctx context.Context, tid int64, keywords string,
	offset, limit int) ([]domain.User, int, error) {
	return l.cache.Query(ctx, tid, keywords, offset, limit)
}

// RefreshCacheUserWithPager 通过 LDAP 分页遍历拉取远端用户并重建本地缓存索引
func (l *ldapService) RefreshCacheUserWithPager(ctx context.Context, tid int64) error {
	config, ok := getLDAPConfig(ctx, l.idsSvc)
	if !ok {
		return errors.New("未找到启用的 LDAP 身份源配置")
	}

	client := newClient(config)
	filter := config.SyncUserFilter
	if filter == "" {
		filter = config.UserFilter
	}

	entries, err := client.SearchWithPaging(ctx, filter, getRequiredAttributes(config), 500)
	if err != nil {
		return err
	}

	ldapUsers := make([]domain.User, 0, len(entries))
	for _, entry := range entries {
		ldapUsers = append(ldapUsers, buildDomainUser(entry, config))
	}

	return l.cache.Document(ctx, tid, ldapUsers)
}

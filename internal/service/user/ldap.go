package user

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/service/user/ldapx"
)

type LdapService interface {
	Login(ctx context.Context, username, password string) (domain.User, error)
	SearchCacheUserWithPager(ctx context.Context, keywords string, offset, limit int) ([]domain.User, int, error)
	RefreshCacheUserWithPager(ctx context.Context) error
	Sync(ctx context.Context, users []domain.User) error
}

type ldapService struct {
	repo  repository.IUserRepository
	ldap  ldapx.LdapProvider
	cache cache.RedisearchLdapUserCache
}

func NewLdapService(repo repository.IUserRepository, conf ldapx.Config, cache cache.RedisearchLdapUserCache) LdapService {
	return &ldapService{
		repo:  repo,
		ldap:  ldapx.NewLdap(conf),
		cache: cache,
	}
}

func (l *ldapService) Sync(ctx context.Context, users []domain.User) error {
	return l.repo.BatchUpsert(ctx, users)
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

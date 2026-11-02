package cache

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/redis/go-redis/v9"
)

// IRoleCache 角色元数据与内联权限策略的专属缓存接口
//
//go:generate mockgen -package=cachemocks -destination=./mocks/role.mock.go github.com/Duke1616/eiam/internal/repository/cache IRoleCache
type IRoleCache interface {
	// GetRoleByCode 获取指定租户下的单条角色详情；hit 为 true 表示命中缓存
	GetRoleByCode(ctx context.Context, tid int64, code string) (domain.Role, bool, error)
	// SetRoleByCode 缓存指定租户下的单条角色详情
	SetRoleByCode(ctx context.Context, tid int64, code string, role domain.Role) error
	// DeleteRoleByCode 驱逐单条角色详情缓存
	DeleteRoleByCode(ctx context.Context, tid int64, code string) error
	// DeleteRolesByCodes 批量驱逐角色详情缓存
	DeleteRolesByCodes(ctx context.Context, tid int64, codes []string) error

	// GetRolesByCodes 批量获取角色详情；返回命中字典与未命中代码切片
	GetRolesByCodes(ctx context.Context, tid int64, codes []string) (map[string]domain.Role, []string, error)
	// SetRoles 批量回写角色详情缓存 (基于 Pipeline)
	SetRoles(ctx context.Context, tid int64, roles []domain.Role) error
}

type roleCache struct {
	entity *EntityCache[domain.Role]
}

// NewRoleCache 创建角色仓储缓存实例
func NewRoleCache(client redis.Cmdable) IRoleCache {
	return &roleCache{
		entity: NewEntityCache[domain.Role](
			client,
			"role:detail",
			30*time.Minute,
			func(r domain.Role) string { return r.Code },
		),
	}
}

func (c *roleCache) GetRoleByCode(ctx context.Context, tid int64, code string) (domain.Role, bool, error) {
	return c.entity.Get(ctx, tid, code)
}

func (c *roleCache) SetRoleByCode(ctx context.Context, tid int64, code string, role domain.Role) error {
	return c.entity.Set(ctx, tid, code, role)
}

func (c *roleCache) DeleteRoleByCode(ctx context.Context, tid int64, code string) error {
	return c.entity.Delete(ctx, tid, code)
}

func (c *roleCache) DeleteRolesByCodes(ctx context.Context, tid int64, codes []string) error {
	return c.entity.DeleteMulti(ctx, tid, codes)
}

func (c *roleCache) GetRolesByCodes(ctx context.Context, tid int64, codes []string) (map[string]domain.Role, []string, error) {
	return c.entity.GetMulti(ctx, tid, codes)
}

func (c *roleCache) SetRoles(ctx context.Context, tid int64, roles []domain.Role) error {
	return c.entity.SetMulti(ctx, tid, roles)
}

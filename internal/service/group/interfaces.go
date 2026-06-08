package group

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
)

type IGroupService interface {
	Create(ctx context.Context, g domain.Group) (int64, error)
	Update(ctx context.Context, g domain.Group) error
	Delete(ctx context.Context, id int64) error
	List(ctx context.Context, offset, limit int64) ([]domain.Group, int64, error)
	GetByCode(ctx context.Context, code string) (domain.Group, error)

	// 组用户关系操作 (含 Casbin g 规则联锁)
	AssignMembers(ctx context.Context, groupCode string, usernames []string) (bool, error)
	RemoveMembers(ctx context.Context, groupCode string, usernames []string) (bool, error)
	ListMembers(ctx context.Context, groupCode string, offset, limit int64, keyword string) ([]domain.User, int64, error)

	// 组角色关联
	AssignRole(ctx context.Context, groupCode string, roleCode string) (bool, error)
	RemoveRole(ctx context.Context, groupCode string, roleCode string) (bool, error)
	ListRoles(ctx context.Context, groupCode string) ([]string, error)
}

package group

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
)

// IGroupService 用户组服务接口
type IGroupService interface {
	// Create 新建用户组
	Create(ctx context.Context, g domain.Group) (int64, error)
	// Update 修改用户组基本属性
	Update(ctx context.Context, g domain.Group) error
	// Delete 删除用户组，连带清理该组的 Casbin 分组和角色关联规则
	Delete(ctx context.Context, id int64) error
	// List 分页获取所有用户组列表
	List(ctx context.Context, offset, limit int64) ([]domain.Group, int64, error)
	// Search 分页模糊搜索用户组
	Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.Group, error)
	// CountSearch 模糊搜索匹配的用户组总数量
	CountSearch(ctx context.Context, keyword string) (int64, error)
	// GetByCode 根据组唯一标识码获取用户组详情
	GetByCode(ctx context.Context, code string) (domain.Group, error)

	// AssignMembers 批量添加成员到用户组 (在 DB 中建立绑定，并在 Casbin 中注册用户加入组的 g 规则)
	AssignMembers(ctx context.Context, groupCode string, usernames []string) (bool, error)
	// RemoveMembers 从用户组批量移出成员 (从 DB 中解绑，并从 Casbin 中注销用户加入组的 g 规则)
	RemoveMembers(ctx context.Context, groupCode string, usernames []string) (bool, error)
	// ListMembers 分页列出用户组下的成员列表，支持模糊过滤
	ListMembers(ctx context.Context, groupCode string, offset, limit int64, keyword string) ([]domain.User, int64, error)

	// ListAttachedGroupsByUser 分页获取用户所属的用户组列表，支持用户名或用户ID两种筛选方式
	ListAttachedGroupsByUser(ctx context.Context, username string, userID int64, offset, limit int64, keyword string) ([]domain.Group, int64, error)
	// ListAttachedGroupsByRole 分页获取绑定该角色的用户组列表
	ListAttachedGroupsByRole(ctx context.Context, roleCode string, offset, limit int64, keyword string) ([]domain.Group, int64, error)

	// AssignRole 给用户组授权角色 (在 Casbin 中注册组关联角色的 g 规则)
	AssignRole(ctx context.Context, groupCode string, roleCode string) (bool, error)
	// RemoveRole 取消用户组授权的角色 (从 Casbin 中注销组关联角色的 g 规则)
	RemoveRole(ctx context.Context, groupCode string, roleCode string) (bool, error)
	// ListRoles 列出该用户组拥有的所有角色编码
	ListRoles(ctx context.Context, groupCode string) ([]string, error)
}

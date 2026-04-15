package permission

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
)

// IPermissionService 权限逻辑中心
//
//go:generate mockgen -source=./interfaces.go -package=permissionmocks -destination=./mocks/permission.mock.go -typed IPermissionService
type IPermissionService interface {
	// --- 1. 鉴权决策 (Runtime) ---

	// CheckAPI 针对物理接口访问进行判定
	CheckAPI(ctx context.Context, username string, serviceName, method, path string) (bool, error)
	// CheckPermission 用户是否拥有在该租户下对具体 URN 的特定 Action 权限
	CheckPermission(ctx context.Context, username string, action, resourceURN string) (bool, error)
	// GetAuthorizedMenus 过滤用户拥有的前端菜单
	GetAuthorizedMenus(ctx context.Context, username string) (domain.MenuTree, error)

	// --- 2. 能力中心 (Admin) ---

	// CreatePermission 注册一个全局标准功能 (如 iam:user:view)
	CreatePermission(ctx context.Context, p domain.Permission) (int64, error)
	// GetByCode 获取能力项元数据
	GetByCode(ctx context.Context, code string) (domain.Permission, error)
	// GetPermissionManifest 获取归一化的权限资产清单
	GetPermissionManifest(ctx context.Context) (domain.PermissionManifest, error)
	// BindResourcesToPermission 定义该功能码涵盖哪些物理资源 URN
	BindResourcesToPermission(ctx context.Context, permId int64, permCode string, resURNs []string) error

	// --- 3. 关系管理 (Relation) ---

	// AssignRoleToUser 绑定用户与角色
	AssignRoleToUser(ctx context.Context, username string, roleCode string) (bool, error)
	// AssignRoleInheritance 设置角色继承关系，让 childRole 自动拥有 parentRole 的所有能力
	AssignRoleInheritance(ctx context.Context, childRole string, parentRole string) (bool, error)
	// GetRolesForUser 获取用户的有效角色 (包含隐式继承树中所有的角色)
	GetRolesForUser(ctx context.Context, username string) ([]string, error)

	// AssignPolicyToUser 直接给用户绑定特定的策略
	AssignPolicyToUser(ctx context.Context, username string, policyCode string) (bool, error)
	// AssignPolicyToRole 给角色挂载特定的策略
	AssignPolicyToRole(ctx context.Context, roleCode, policyCode string) (bool, error)
	// GetImplicitSubjectsForUser 解析用户的有效身份图谱 (递归获取所有相关的 Role 和 Policy ID)
	GetImplicitSubjectsForUser(ctx context.Context, username string) ([]string, error)
	// ListAuthorizations 获取授权关系列表 (聚合显示)
	ListAuthorizations(ctx context.Context, query domain.AuthorizationQuery) ([]domain.Authorization, int64, error)
	// SearchSubjects 全域搜索授权主体 (用户/角色)
	SearchSubjects(ctx context.Context, keyword string, subType string, offset, limit int) ([]domain.Subject, int64, error)
}

// AuthorizationProvider 授权关系查询提供者接口
type AuthorizationProvider interface {
	// ObjType 返回该提供者支持的目标类型
	ObjType() domain.AuthorizationObjType
	// ListAuthorizations 查询授权关系
	ListAuthorizations(ctx context.Context, query domain.AuthorizationQuery) ([]domain.Authorization, int64, error)
}

// roleAuthorizationProvider 角色授权提供者
type roleAuthorizationProvider struct {
	service *permissionService
}

func (p *roleAuthorizationProvider) ObjType() domain.AuthorizationObjType {
	return domain.AuthObjRole
}

func (p *roleAuthorizationProvider) ListAuthorizations(ctx context.Context, query domain.AuthorizationQuery) ([]domain.Authorization, int64, error) {
	return p.service.listRoleAuthorizations(ctx, query)
}

// policyAuthorizationProvider 策略授权提供者
type policyAuthorizationProvider struct {
	service *permissionService
}

func (p *policyAuthorizationProvider) ObjType() domain.AuthorizationObjType {
	return domain.AuthObjSystemPolicy
}

func (p *policyAuthorizationProvider) ListAuthorizations(ctx context.Context, query domain.AuthorizationQuery) ([]domain.Authorization, int64, error) {
	return p.service.listPolicyAuthorizations(ctx, query)
}

package permission

import (
	"context"
	"fmt"

	"github.com/Duke1616/eiam/internal/authz"
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/casbin/casbin/v2"
)

// IPermissionService 权限管理与决策中心
//
//go:generate mockgen -source=./permission.go -package=permissionmocks -destination=./mocks/permission.mock.go -typed IPermissionService
type IPermissionService interface {
	// --- 1. 鉴权决策 (Runtime) ---

	// CheckAPI 核心动作：针对物理接口访问进行鉴权
	CheckAPI(ctx context.Context, tenantId int64, userId int64, serviceName, method, path string) (bool, error)
	// CheckPermission 针对特定能力码执行 OPA 鉴权
	CheckPermission(ctx context.Context, tenantId int64, userId int64, action, resource string) (bool, error)
	// GetAuthorizedMenus 获取用户授权后可见的菜单列表
	GetAuthorizedMenus(ctx context.Context, tenantId int64, userId int64) ([]domain.Menu, error)

	// --- 2. 权限项与资源绑定关系管理 (Admin) ---

	// CreatePermission 定义一个新的逻辑权限点 (能力码)
	CreatePermission(ctx context.Context, p domain.Permission) (int64, error)
	// BindResourceToPermission 将物理资源(API/Menu)绑定到指定的权限码上
	BindResourceToPermission(ctx context.Context, tenantId int64, permCode string, resType domain.ResourceType, resIds []int64) error

	// --- 3. 用户与角色的分配关系管理 (Relation) ---

	// AssignRoleToUser 给用户分配角色
	AssignRoleToUser(ctx context.Context, tenantId int64, userId int64, roleCode string) (bool, error)
	// GetRolesForUser 计算用户在特定租户下的全量角色
	GetRolesForUser(ctx context.Context, tenantId int64, userId int64) ([]string, error)
}

type PermissionService struct {
	enforcer    *casbin.SyncedEnforcer
	roleSvc     role.IRoleService
	resourceSvc resource.IResourceService
	permRepo    repository.IPermissionRepository
	authorizer  authz.IAuthorizer
}

// NewPermissionService 创建权限服务实例
// NOTE: 这里的依赖已变更为其它服务接口，而非跨域 Repository
func NewPermissionService(
	en *casbin.SyncedEnforcer,
	roleSvc role.IRoleService,
	resourceSvc resource.IResourceService,
	permRepo repository.IPermissionRepository,
	auth authz.IAuthorizer) IPermissionService {
	return &PermissionService{
		enforcer:    en,
		roleSvc:     roleSvc,
		resourceSvc: resourceSvc,
		permRepo:    permRepo,
		authorizer:  auth,
	}
}

// --- 鉴权决策实现 ---

func (s *PermissionService) CheckAPI(ctx context.Context, tenantId int64, userId int64, serviceName, method, path string) (bool, error) {
	// 调用 IResourceService 查找物理 API
	api, err := s.resourceSvc.FindAPIByPath(ctx, serviceName, method, path)
	if err != nil {
		return false, fmt.Errorf("api not found: %s %s %s", serviceName, method, path)
	}

	// 查找该资源绑定的能力码 (本服务 Repository)
	codes, err := s.permRepo.FindCodesByResource(ctx, domain.ResAPI, api.ID)
	if err != nil {
		return false, err
	}

	for _, code := range codes {
		ok, err := s.CheckPermission(ctx, tenantId, userId, code, "*")
		if err == nil && ok {
			return true, nil
		}
	}
	return false, nil
}

func (s *PermissionService) CheckPermission(ctx context.Context, tenantId int64, userId int64, action, resource string) (bool, error) {
	roleCodes, err := s.GetRolesForUser(ctx, tenantId, userId)
	if err != nil {
		return false, err
	}

	// 调用 IRoleService 获取全量角色的 Policy JSON
	roles, err := s.roleSvc.ListByIncludeCodes(ctx, tenantId, roleCodes)
	if err != nil {
		return false, err
	}

	var allPolicies []domain.Policy
	for _, r := range roles {
		allPolicies = append(allPolicies, r.Policies...)
	}

	return s.authorizer.Authorize(ctx, authz.AuthInput{
		Action:   action,
		Resource: resource,
		Policies: allPolicies,
	})
}

func (s *PermissionService) GetAuthorizedMenus(ctx context.Context, tenantId int64, userId int64) ([]domain.Menu, error) {
	// 通过 IResourceService 获取全量菜单
	allMenus, err := s.resourceSvc.ListMenus(ctx, tenantId)
	if err != nil {
		return nil, err
	}

	var authorizedMenus []domain.Menu
	for _, menu := range allMenus {
		codes, err := s.permRepo.FindCodesByResource(ctx, domain.ResMenu, menu.ID)
		if err != nil || len(codes) == 0 {
			authorizedMenus = append(authorizedMenus, menu)
			continue
		}

		for _, code := range codes {
			ok, err := s.CheckPermission(ctx, tenantId, userId, code, "*")
			if err == nil && ok {
				authorizedMenus = append(authorizedMenus, menu)
				break
			}
		}
	}
	return authorizedMenus, nil
}

// --- 管理逻辑实现 ---

func (s *PermissionService) CreatePermission(ctx context.Context, p domain.Permission) (int64, error) {
	return s.permRepo.CreatePermission(ctx, p)
}

// BindResourceToPermission 核心：建立逻辑码与物理资源的绑定关系
func (s *PermissionService) BindResourceToPermission(ctx context.Context, tenantId int64, permCode string, resType domain.ResourceType, resIds []int64) error {
	p, err := s.permRepo.GetByCode(ctx, tenantId, permCode)
	if err != nil {
		return fmt.Errorf("permission code %s not found: %w", permCode, err)
	}

	return s.permRepo.BindResources(ctx, tenantId, p.ID, p.Code, resType, resIds)
}

// --- 用户角色关系实现 ---

func (s *PermissionService) AssignRoleToUser(ctx context.Context, tenantId int64, userId int64, roleCode string) (bool, error) {
	sub := fmt.Sprintf("user:%d", userId)
	tenant := fmt.Sprintf("tenant:%d", tenantId)
	return s.enforcer.AddGroupingPolicy(sub, roleCode, tenant)
}

func (s *PermissionService) GetRolesForUser(ctx context.Context, tenantId int64, userId int64) ([]string, error) {
	sub := fmt.Sprintf("user:%d", userId)
	tenant := fmt.Sprintf("tenant:%d", tenantId)
	return s.enforcer.GetRolesForUserInDomain(sub, tenant), nil
}

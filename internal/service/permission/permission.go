package permission

import (
	"context"
	"strconv"

	"github.com/Duke1616/eiam/internal/authz"
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/urn"
	"github.com/casbin/casbin/v2"
)

// IPermissionService 权限逻辑中心
//
//go:generate mockgen -source=./permission.go -package=permissionmocks -destination=./mocks/permission.mock.go -typed IPermissionService
type IPermissionService interface {
	// --- 1. 鉴权决策 (Runtime) ---

	// CheckAPI 针对物理接口访问进行判定
	CheckAPI(ctx context.Context, userId int64, serviceName, method, path string) (bool, error)
	// CheckPermission 用户是否拥有在该租户下对具体 URN 的特定 Action 权限
	CheckPermission(ctx context.Context, userId int64, action, resourceURN string) (bool, error)
	// GetAuthorizedMenus 过滤用户拥有的前端菜单
	GetAuthorizedMenus(ctx context.Context, userId int64) ([]domain.Menu, error)

	// --- 2. 能力中心 (Admin) ---

	// CreatePermission 注册一个全局标准功能 (如 iam:user:view)
	CreatePermission(ctx context.Context, p domain.Permission) (int64, error)
	// BindResourcesToPermission 定义该功能码涵盖哪些物理资源 ID
	BindResourcesToPermission(ctx context.Context, permId int64, permCode string, resType domain.ResourceType, resIds []int64) error

	// --- 3. 关系管理 (Relation) ---

	// AssignRoleToUser 绑定用户与角色
	AssignRoleToUser(ctx context.Context, userId int64, roleCode string) (bool, error)
	// GetRolesForUser 获取用户的有效角色
	GetRolesForUser(ctx context.Context, userId int64) ([]string, error)
}

type permissionService struct {
	enforcer    *casbin.SyncedEnforcer
	roleSvc     role.IRoleService
	resourceSvc resource.IResourceService
	permRepo    repository.IPermissionRepository
	authorizer  authz.IAuthorizer
}

func NewPermissionService(
	en *casbin.SyncedEnforcer,
	roleSvc role.IRoleService,
	resourceSvc resource.IResourceService,
	permRepo repository.IPermissionRepository,
	auth authz.IAuthorizer) IPermissionService {
	return &permissionService{
		enforcer:    en,
		roleSvc:     roleSvc,
		resourceSvc: resourceSvc,
		permRepo:    permRepo,
		authorizer:  auth,
	}
}

// CheckAPI 判定请求合法性
func (s *permissionService) CheckAPI(ctx context.Context, userId int64, serviceName, method, path string) (bool, error) {
	// 1. 定位物理 API
	api, err := s.resourceSvc.FindAPIByPath(ctx, serviceName, method, path)
	if err != nil {
		return false, err
	}
	
	// 如果 API 在系统中根本未注册，实施防误闯（Fail-closed）拦截
	if api.ID == 0 {
		return false, nil
	}

	// 2. 反查该物理资产在全局绑定了哪些逻辑能力码
	codes, err := s.permRepo.FindCodesByResource(ctx, domain.ResourceTypeAPI, api.ID)
	if err != nil {
		return false, err
	}

	// 3. 如果没绑定任何码，视为公共接口，直接放行
	if len(codes) == 0 {
		return true, nil
	}

	// 4. 构建 URN 进行判定
	tenantId := ctxutil.GetTenantID(ctx)
	resURN := urn.New(strconv.FormatInt(tenantId, 10), serviceName, "api", path).String()

	// 5. 用户只要拥有其中任何一项能力的授权，即可通过
	for _, code := range codes {
		ok, err := s.CheckPermission(ctx, userId, code, resURN)
		if err == nil && ok {
			return true, nil
		}
	}

	return false, nil
}

func (s *permissionService) CheckPermission(ctx context.Context, userId int64, action, resourceURN string) (bool, error) {
	tenantId := ctxutil.GetTenantID(ctx)
	roleCodes, err := s.GetRolesForUser(ctx, userId)
	if err != nil {
		return false, err
	}

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
		Resource: resourceURN,
		Policies: allPolicies,
	})
}

// GetAuthorizedMenus 过滤授权菜单
func (s *permissionService) GetAuthorizedMenus(ctx context.Context, userId int64) ([]domain.Menu, error) {
	tenantId := ctxutil.GetTenantID(ctx)
	allMenus, err := s.resourceSvc.ListMenus(ctx, tenantId)
	if err != nil {
		return nil, err
	}

	var authorizedMenus []domain.Menu
	for _, menu := range allMenus {
		// 反查菜单对应的逻辑码
		codes, err := s.permRepo.FindCodesByResource(ctx, domain.ResourceTypeMenu, menu.ID)
		if err != nil || len(codes) == 0 {
			// 未映射能力的菜单视为公共菜单
			authorizedMenus = append(authorizedMenus, menu)
			continue
		}

		resURN := urn.New(strconv.FormatInt(tenantId, 10), "iam", "menu", menu.Path).String()

		isAuth := false
		for _, code := range codes {
			ok, _ := s.CheckPermission(ctx, userId, code, resURN)
			if ok {
				isAuth = true
				break
			}
		}

		if isAuth {
			authorizedMenus = append(authorizedMenus, menu)
		}
	}
	return authorizedMenus, nil
}

func (s *permissionService) CreatePermission(ctx context.Context, p domain.Permission) (int64, error) {
	return s.permRepo.CreatePermission(ctx, p)
}

func (s *permissionService) BindResourcesToPermission(ctx context.Context, permId int64, permCode string, resType domain.ResourceType, resIds []int64) error {
	return s.permRepo.BindResources(ctx, permId, permCode, resType, resIds)
}

func (s *permissionService) AssignRoleToUser(ctx context.Context, userId int64, roleCode string) (bool, error) {
	sub := strconv.FormatInt(userId, 10)
	tenant := strconv.FormatInt(ctxutil.GetTenantID(ctx), 10)
	return s.enforcer.AddGroupingPolicy(sub, roleCode, tenant)
}

func (s *permissionService) GetRolesForUser(ctx context.Context, userId int64) ([]string, error) {
	sub := strconv.FormatInt(userId, 10)
	tenant := strconv.FormatInt(ctxutil.GetTenantID(ctx), 10)
	return s.enforcer.GetRolesForUserInDomain(sub, tenant), nil
}

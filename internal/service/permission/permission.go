package permission

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Duke1616/eiam/internal/authz"
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/urn"
	"github.com/casbin/casbin/v2"
	"github.com/ecodeclub/ekit/slice"
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
	// AssignRoleInheritance 设置角色继承关系，让 childRole 自动拥有 parentRole 的所有能力
	AssignRoleInheritance(ctx context.Context, childRole string, parentRole string) (bool, error)
	// GetRolesForUser 获取用户的有效角色 (包含隐式继承树中所有的角色)
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
	// 1. 获取用户关联的所有角色
	roleCodes, err := s.GetRolesForUser(ctx, userId)
	if err != nil {
		return false, err
	}

	// 2. 构建资源 URN 与 Pseudo Action
	tenantId := ctxutil.GetTenantID(ctx)
	resURN := urn.New(strconv.FormatInt(tenantId, 10), serviceName, "api", path).String()

	actionPath := strings.TrimPrefix(path, "/")
	actionPath = strings.ReplaceAll(actionPath, "/", ":")
	pseudoAction := fmt.Sprintf("%s:%s", serviceName, actionPath)

	// 3. 优先执行上帝模式/熔断判定 (全量语义匹配)
	ok, err := s.invokeAuthorize(ctx, roleCodes, pseudoAction, resURN)
	if err == nil && ok {
		return true, nil
	}

	// 4. 定位物理 API
	api, err := s.resourceSvc.FindAPIByPath(ctx, serviceName, method, path)
	if err != nil || api.ID == 0 {
		return false, err
	}

	// 5. 反查该物理资产关联的逻辑能力码
	codes, err := s.permRepo.FindCodesByResource(ctx, domain.ResourceTypeAPI, api.ID)
	if err != nil || len(codes) == 0 {
		return false, err
	}

	// 6. 只要具备其中任何一项能力码的授权即可
	for _, code := range codes {
		ok, err = s.invokeAuthorize(ctx, roleCodes, code, resURN)
		if err == nil && ok {
			return true, nil
		}
	}

	return false, nil
}

func (s *permissionService) CheckPermission(ctx context.Context, userId int64, action, resourceURN string) (bool, error) {
	roleCodes, err := s.GetRolesForUser(ctx, userId)
	if err != nil {
		return false, err
	}
	return s.invokeAuthorize(ctx, roleCodes, action, resourceURN)
}

// invokeAuthorize 统一调用 OPA 判定的私有方法
func (s *permissionService) invokeAuthorize(ctx context.Context, roleCodes []string, action, resourceURN string) (bool, error) {
	// 1. 加载角色的具体 Policies 文档
	roles, err := s.roleSvc.ListByIncludeCodes(ctx, roleCodes)
	if err != nil {
		return false, err
	}

	var allPolicies []domain.Policy
	var hasSuperAdmin bool
	for _, r := range roles {
		if r.Code == "SUPER_ADMIN" {
			hasSuperAdmin = true
		}
		allPolicies = append(allPolicies, r.Policies...)
	}

	// 2. 超级管理员：逻辑上注入一条 Allow * 的策略，但放在列表最前/最后，确保 Deny 优先级
	// 注意：OPA 判定的具体 Rego 逻辑决定了如何处理。
	// 如果 OPA 逻辑是 "Allow if any matches and NO Deny matches"，那么注入这一条即可。
	if hasSuperAdmin {
		allPolicies = append(allPolicies, domain.Policy{
			Name:    "SUPER_ADMIN_OVERRIDE",
			Version: "2026-04-03",
			Statement: []domain.Statement{
				{
					Effect:   domain.Allow,
					Action:   []string{"*"},
					Resource: []string{"*"},
				},
			},
		})
	}

	fmt.Printf("DEBUG: invokeAuthorize - action: %s, res: %s, policies_count: %d\n", action, resourceURN, len(allPolicies))

	// 3. 提交给 OPA 引擎进行 Rego 判定
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
	tenantId := ctxutil.GetTenantID(ctx)

	return s.enforcer.AddGroupingPolicy(sub, roleCode, strconv.FormatInt(tenantId, 10))
}

func (s *permissionService) AssignRoleInheritance(ctx context.Context, childRole string, parentRole string) (bool, error) {
	tenantId := ctxutil.GetTenantID(ctx)

	return s.enforcer.AddGroupingPolicy(childRole, parentRole, strconv.FormatInt(tenantId, 10))
}

func (s *permissionService) GetRolesForUser(ctx context.Context, userId int64) ([]string, error) {
	sub := strconv.FormatInt(userId, 10)
	tid := strconv.FormatInt(ctxutil.GetTenantID(ctx), 10)

	// 1. 本地链路解析
	// 得益于 ioc/casbin.go 中的 AddDomainMatchingFunc("0") 配置：
	// 当我们查询 tid 时，Casbin 会自动将 tid 匹配到域 "0"，并在内部图搜索中完成：
	// - 租户级继承 (g, A, B, tid)
	// - 全局继承 (g, ADMIN, READER, 0)
	// - 跨域继承 (g, A, ADMIN, tid)
	// - 乃至直接分配的全局角色 (g, sub, SUPER_ADMIN, 0)
	// 所有的路径都在这一行解析器内自动闭环。
	allPotentialCodes, err := s.enforcer.GetImplicitRolesForUser(sub, tid)
	if err != nil {
		return nil, err
	}

	if len(allPotentialCodes) == 0 {
		return []string{}, nil
	}

	// 2. 最后通过数据库进行物理隔离过滤
	roles, err := s.roleSvc.ListByIncludeCodes(ctx, allPotentialCodes)
	if err != nil {
		return nil, err
	}

	// 3. 提取最终有效的 Role Code
	return slice.Map(roles, func(idx int, r domain.Role) string {
		return r.Code
	}), nil
}

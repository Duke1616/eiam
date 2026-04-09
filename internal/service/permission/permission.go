package permission

import (
	"context"
	"strconv"

	"github.com/Duke1616/eiam/internal/authz"
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/pkg/ctxutil"
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
	// GetByCode 获取能力项元数据
	GetByCode(ctx context.Context, code string) (domain.Permission, error)
	// BindResourcesToPermission 定义该功能码涵盖哪些物理资源 URN
	BindResourcesToPermission(ctx context.Context, permId int64, permCode string, resURNs []string) error

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

// CheckAPI 针对物理接口访问进行判定
func (s *permissionService) CheckAPI(ctx context.Context, userId int64, serviceName, method, path string) (bool, error) {
	// 1. 物理层拦截：未注册的物理资产视为不存在，严禁任何访问 (Fail-closed)
	api, err := s.resourceSvc.FindAPIByPath(ctx, serviceName, method, path)
	if err != nil || api.ID == 0 {
		return false, err
	}

	// 2. 映射层发现：物理资产必须至少挂载一个逻辑能力码 (Permission Code) 才能进行业务判定
	codes, err := s.permRepo.FindCodesByResource(ctx, api.URN())
	if err != nil || len(codes) == 0 {
		return false, nil
	}

	// 3. 策略预加载：获取用户及其继承链路的所有有效策略文档
	policies, err := s.getEffectivePolicies(ctx, userId)
	if err != nil {
		return false, err
	}

	// 4. OPA 裁决：一次性提交该 API 的所有身份码，让 OPA 处理“全局允许 (SUPER_ADMIN *)”与“特定熔断 (ADMIN Deny)”
	return s.authorizer.Authorize(ctx, authz.AuthInput{
		Actions:  codes,
		Resource: api.URN(),
		Policies: policies,
	})
}

// CheckPermission 针对特定 URN 的直接 Action 匹配 (用于 UI 渲染、菜单显示等逻辑)
func (s *permissionService) CheckPermission(ctx context.Context, userId int64, action, resourceURN string) (bool, error) {
	policies, err := s.getEffectivePolicies(ctx, userId)
	if err != nil {
		return false, err
	}

	return s.authorizer.Authorize(ctx, authz.AuthInput{
		Actions:  []string{action},
		Resource: resourceURN,
		Policies: policies,
	})
}

// GetAuthorizedMenus 过滤授权菜单并构建层级树 (重构版：逻辑清晰、职责分离)
func (s *permissionService) GetAuthorizedMenus(ctx context.Context, userId int64) ([]domain.Menu, error) {
	// 1. 数据准备：加载资产全集、染色映射及用户策略
	allMenus, err := s.resourceSvc.ListAllMenus(ctx)
	if err != nil || len(allMenus) == 0 {
		return []domain.Menu{}, err
	}

	menuURNs := slice.Map(allMenus, func(_ int, m domain.Menu) string { return m.URN() })
	codesMap, err := s.permRepo.FindCodesByResourceURNs(ctx, menuURNs)
	if err != nil {
		return nil, err
	}

	policies, err := s.getEffectivePolicies(ctx, userId)
	if err != nil {
		return nil, err
	}

	// 2. 批量鉴权：利用 OPA 向量化能力一次性判定所有 URN
	allowedURNs, err := s.authorizer.AuthorizeBatch(ctx, authz.AuthInput{
		BatchResources:  menuURNs,
		ResourceActions: s.buildResourceActionMap(menuURNs, codesMap),
		Policies:        policies,
	})
	if err != nil {
		return nil, err
	}

	// 3. 结果精炼：合并 OPA 判权结果与“公共菜单”放行逻辑
	authorizedNodes := s.filterAccessibleMenus(allMenus, codesMap, allowedURNs)

	// 4. 结构构建：构建高性能树形视图
	return s.buildMenuTree(authorizedNodes), nil
}

// buildResourceActionMap 构建 URN -> 动作候选集的映射表
func (s *permissionService) buildResourceActionMap(urns []string, codesMap map[string][]string) map[string][]string {
	resActions := make(map[string][]string, len(urns))
	for _, u := range urns {
		actions := []string{"*"} // 默认通配符
		if codes, ok := codesMap[u]; ok {
			actions = append(actions, codes...)
		}
		resActions[u] = actions
	}
	return resActions
}

// filterAccessibleMenus 根据 OPA 允许列表及公共资产定义，筛选最终可见节点
func (s *permissionService) filterAccessibleMenus(all []domain.Menu, codesMap map[string][]string, allowedURNs []string) []domain.Menu {
	allowedSet := make(map[string]string, len(allowedURNs))
	for _, u := range allowedURNs {
		allowedSet[u] = u
	}

	res := make([]domain.Menu, 0)
	for _, m := range all {
		mURN := m.URN()
		_, isAllowed := allowedSet[mURN]
		_, isBound := codesMap[mURN]

		// 判权通过 OR 服务端未对其进行任何权限染色的资产（公共资产）
		if isAllowed || !isBound {
			res = append(res, m)
		}
	}
	return res
}

// getEffectivePolicies 聚合用户在当前上下文下的所有有效策略 (含系统预设逻辑)
func (s *permissionService) getEffectivePolicies(ctx context.Context, userId int64) ([]domain.Policy, error) {
	// 1. 获取用户关联的所有角色 Code (通过底层穿透后的全链路结果)
	roleCodes, err := s.GetRolesForUser(ctx, userId)
	if err != nil {
		return nil, err
	}

	// 2. 加载角色的具体 Policies 文档 (受 SQL 物理隔离保护)
	roles, err := s.roleSvc.ListByIncludeCodes(ctx, roleCodes)
	if err != nil {
		return nil, err
	}

	var allPolicies []domain.Policy
	for _, r := range roles {
		allPolicies = append(allPolicies, r.Policies...)
	}

	return allPolicies, nil
}

// buildMenuTree 高性能构建树结构
func (s *permissionService) buildMenuTree(nodes []domain.Menu) []domain.Menu {
	nodeMap := make(map[int64]*domain.Menu)
	for i := range nodes {
		menu := nodes[i]
		menu.Children = make([]*domain.Menu, 0)
		nodeMap[menu.ID] = &menu
	}

	var roots []domain.Menu
	for _, m := range nodeMap {
		if m.ParentID == 0 {
			roots = append(roots, *m)
		} else {
			if parent, exists := nodeMap[m.ParentID]; exists {
				parent.Children = append(parent.Children, m)
			}
		}
	}

	for i := range roots {
		if node, exists := nodeMap[roots[i].ID]; exists {
			roots[i].Children = node.Children
		}
	}

	return roots
}

func (s *permissionService) CreatePermission(ctx context.Context, p domain.Permission) (int64, error) {
	return s.permRepo.CreatePermission(ctx, p)
}

func (s *permissionService) GetByCode(ctx context.Context, code string) (domain.Permission, error) {
	return s.permRepo.GetByCode(ctx, code)
}

func (s *permissionService) BindResourcesToPermission(ctx context.Context, permId int64, permCode string, resURNs []string) error {
	return s.permRepo.BindResources(ctx, permId, permCode, resURNs)
}

func (s *permissionService) AssignRoleToUser(ctx context.Context, userId int64, roleCode string) (bool, error) {
	sub := strconv.FormatInt(userId, 10)
	tenantId := ctxutil.GetTenantID(ctx)

	return s.enforcer.AddGroupingPolicy(sub, roleCode, strconv.FormatInt(tenantId, 10))
}

func (s *permissionService) AssignRoleInheritance(ctx context.Context, childRole string, parentRole string) (bool, error) {
	tenantId := ctxutil.GetTenantID(ctx)
	tid := strconv.FormatInt(tenantId, 10)

	// 1. 死循环检测 (Cycle Detection)
	// 如果我们要让 childRole 继承 parentRole (child -> parent)，
	// 那么必须保证 parentRole 此时并没有直接或间接地继承自 childRole。
	// 利用 Casbin 的 GetImplicitRolesForUser 可以查出 parentRole 的所有隐式祖先。
	ancestors, err := s.enforcer.GetImplicitRolesForUser(parentRole, tid)
	if err != nil {
		return false, err
	}

	for _, ancestor := range ancestors {
		if ancestor == childRole {
			return false, errs.ErrRoleCycleInheritance
		}
	}

	return s.enforcer.AddGroupingPolicy(childRole, parentRole, tid)
}

// GetRolesForUser 获取用户的有效角色 (包含隐式继承树中所有的角色)
func (s *permissionService) GetRolesForUser(ctx context.Context, userId int64) ([]string, error) {
	sub := strconv.FormatInt(userId, 10)
	tid := strconv.FormatInt(ctxutil.GetTenantID(ctx), 10)

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

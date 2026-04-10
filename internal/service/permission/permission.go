package permission

import (
	"context"
	"sort"
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
	// 1. 物理层拦截
	api, err := s.resourceSvc.FindAPIByPath(ctx, serviceName, method, path)
	if err != nil || api.ID == 0 {
		return false, err
	}

	// 2. 映射层发现
	codes, err := s.permRepo.FindCodesByResource(ctx, api.URN())
	if err != nil || len(codes) == 0 {
		return false, nil
	}

	// 3. 策略预加载 (优化点：减少重复查询)
	roles, err := s.getEffectiveRoles(ctx, userId)
	if err != nil {
		return false, err
	}

	// 4. OPA 裁决
	return s.authorizer.Authorize(ctx, authz.AuthInput{
		Actions:  codes,
		Resource: api.URN(),
		Policies: s.flattenPolicies(roles),
	})
}

// CheckPermission 针对特定 URN 的直接 Action 匹配
func (s *permissionService) CheckPermission(ctx context.Context, userId int64, action, resourceURN string) (bool, error) {
	roles, err := s.getEffectiveRoles(ctx, userId)
	if err != nil {
		return false, err
	}

	return s.authorizer.Authorize(ctx, authz.AuthInput{
		Actions:  []string{action},
		Resource: resourceURN,
		Policies: s.flattenPolicies(roles),
	})
}

// GetAuthorizedMenus 过滤授权菜单并构建层级树
func (s *permissionService) GetAuthorizedMenus(ctx context.Context, userId int64) ([]domain.Menu, error) {
	allMenus, err := s.resourceSvc.ListAllMenus(ctx)
	if err != nil || len(allMenus) == 0 {
		return []domain.Menu{}, err
	}

	menuURNs := slice.Map(allMenus, func(_ int, m domain.Menu) string { return m.URN() })
	codesMap, err := s.permRepo.FindCodesByResourceURNs(ctx, menuURNs)
	if err != nil {
		return nil, err
	}

	roles, err := s.getEffectiveRoles(ctx, userId)
	if err != nil {
		return nil, err
	}

	allowedURNs, err := s.authorizer.AuthorizeBatch(ctx, authz.AuthInput{
		BatchResources:  menuURNs,
		ResourceActions: s.buildResourceActionMap(menuURNs, codesMap),
		Policies:        s.flattenPolicies(roles),
	})
	if err != nil {
		return nil, err
	}

	authorizedNodes := s.filterAccessibleMenus(allMenus, codesMap, allowedURNs)
	return s.buildMenuTree(authorizedNodes), nil
}

// buildResourceActionMap 构建 URN -> 动作候选集的映射表
func (s *permissionService) buildResourceActionMap(urns []string, codesMap map[string][]string) map[string][]string {
	resActions := make(map[string][]string, len(urns))
	for _, u := range urns {
		actions := []string{"*"}
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
		if isAllowed || !isBound {
			res = append(res, m)
		}
	}
	return res
}

// getEffectiveRoles 获取用户在当前上下文中所有有效的 Role 对象 (含系统角色)
func (s *permissionService) getEffectiveRoles(ctx context.Context, userId int64) ([]domain.Role, error) {
	// 优先从上下文获取 (声明式标识)
	uid := ctxutil.GetUserID(ctx).Int64()
	if uid == 0 {
		uid = userId
	}

	sub := strconv.FormatInt(uid, 10)
	tid := ctxutil.GetTenantID(ctx).String()

	// 1. Casbin 链路解析 (O(1) 内存图搜索)
	roleCodes, err := s.enforcer.GetImplicitRolesForUser(sub, tid)
	if err != nil {
		return nil, err
	}
	if len(roleCodes) == 0 {
		return []domain.Role{}, nil
	}

	// 2. 数据库批量拉取详情 (受租户隔离保护，且支持 Global Override 逻辑)
	return s.roleSvc.ListByIncludeCodes(ctx, roleCodes)
}

// flattenPolicies 压平角色中的策略文档
func (s *permissionService) flattenPolicies(roles []domain.Role) []domain.Policy {
	var policies []domain.Policy
	for _, r := range roles {
		policies = append(policies, r.Policies...)
	}
	return policies
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

	// 对所有节点的子菜单进行排序 (In-place)
	for _, m := range nodeMap {
		if len(m.Children) > 1 {
			sort.Slice(m.Children, func(i, j int) bool {
				return m.Children[i].Sort < m.Children[j].Sort
			})
		}
	}

	// 对根菜单进行排序
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].Sort < roots[j].Sort
	})

	// 重新关联根节点的 Children 指针 (因为之前 roots append 的是副本)
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

// AssignRoleToUser 绑定用户与角色 (增加一致性校验)
func (s *permissionService) AssignRoleToUser(ctx context.Context, userId int64, roleCode string) (bool, error) {
	// 前置校验角色是否存在且合法
	_, err := s.roleSvc.GetByCode(ctx, roleCode)
	if err != nil {
		return false, err
	}

	sub := strconv.FormatInt(userId, 10)
	tid := ctxutil.GetTenantID(ctx).String()
	return s.enforcer.AddGroupingPolicy(sub, roleCode, tid)
}

// AssignRoleInheritance 设置角色继承关系 (增加两端一致性校验)
func (s *permissionService) AssignRoleInheritance(ctx context.Context, childRole string, parentRole string) (bool, error) {
	// 双重验证，严禁为不存在的角色创建继承关系
	if _, err := s.roleSvc.GetByCode(ctx, childRole); err != nil {
		return false, err
	}
	if _, err := s.roleSvc.GetByCode(ctx, parentRole); err != nil {
		return false, err
	}

	tid := ctxutil.GetTenantID(ctx).String()
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

// GetRolesForUser 获取用户的有效角色切片
func (s *permissionService) GetRolesForUser(ctx context.Context, userId int64) ([]string, error) {
	roles, err := s.getEffectiveRoles(ctx, userId)
	if err != nil {
		return nil, err
	}

	return slice.Map(roles, func(_ int, r domain.Role) string {
		return r.Code
	}), nil
}

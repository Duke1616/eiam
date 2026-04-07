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

	// 4. 环境聚合：直接使用资源的唯一身份标识 (URN)
	resURN := api.URN()

	// 5. OPA 裁决：一次性提交该 API 的所有身份码，让 OPA 处理“全局允许 (SUPER_ADMIN *)”与“特定熔断 (ADMIN Deny)”
	return s.authorizer.Authorize(ctx, authz.AuthInput{
		Actions:  codes,
		Resource: resURN,
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

// GetAuthorizedMenus 过滤授权菜单并构建层级树
func (s *permissionService) GetAuthorizedMenus(ctx context.Context, userId int64) ([]domain.Menu, error) {
	// 1. 批量加载物理资产库 (资产全集)
	allMenus, err := s.resourceSvc.ListAllMenus(ctx)
	if err != nil {
		return nil, err
	}
	if len(allMenus) == 0 {
		return []domain.Menu{}, nil
	}

	// 2. 批量加载逻辑映射关系 (找出所有关联的 Code)
	menuURNs := slice.Map(allMenus, func(i int, m domain.Menu) string { return m.URN() })
	codesMap, err := s.permRepo.FindCodesByResourceURNs(ctx, menuURNs)
	if err != nil {
		return nil, err
	}

	// 3. 预加载用户全局策略集
	policies, err := s.getEffectivePolicies(ctx, userId)
	if err != nil {
		return nil, err
	}

	// 4. 内存过滤：判定哪些菜单允许访问
	var authorizedNodes []domain.Menu
	for _, menu := range allMenus {
		// 收集该菜单的 Actions 候选集
		candidates := []string{"*"}
		mURN := menu.URN()
		if codes, ok := codesMap[mURN]; ok {
			candidates = append(candidates, codes...)
		} else {
			// NOTE: 未映射能力的菜单视为公共菜单 (根据业务策略决定是否放行)
			authorizedNodes = append(authorizedNodes, menu)
			continue
		}

		resURN := menu.URN()
		ok, err := s.authorizer.Authorize(ctx, authz.AuthInput{
			Actions:  candidates,
			Resource: resURN,
			Policies: policies,
		})

		if err == nil && ok {
			authorizedNodes = append(authorizedNodes, menu)
		}
	}

	// 5. 高性能构建菜单树 (O(N) 复杂度)
	return s.buildMenuTree(authorizedNodes), nil
}

// buildMenuTree 高性能构建树结构
func (s *permissionService) buildMenuTree(nodes []domain.Menu) []domain.Menu {
	nodeMap := make(map[int64]*domain.Menu)
	for i := range nodes {
		// 复制一份，避免切片底层冲突，并初始化 Children
		menu := nodes[i]
		menu.Children = make([]*domain.Menu, 0)
		nodeMap[menu.ID] = &menu
	}

	var roots []domain.Menu
	for _, m := range nodeMap {
		if m.ParentID == 0 {
			roots = append(roots, *m)
		} else {
			// 只有父节点也被授权了，子节点才挂载上去 (或者你可以选择在这里保留断层)
			if parent, exists := nodeMap[m.ParentID]; exists {
				parent.Children = append(parent.Children, m)
			}
		}
	}

	// 重新把 root 里的 children 指针更新 (因为上面 Map 里更新的是指针)
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

	return s.enforcer.AddGroupingPolicy(childRole, parentRole, strconv.FormatInt(tenantId, 10))
}

// GetRolesForUser 获取用户的有效角色 (包含隐式继承树中所有的角色)
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

func (s *permissionService) buildResourceURN(ctx context.Context, service, resScope, path string) string {
	// 修正：全局资产身份统一使用租户 "0"
	return urn.New("0", service, resScope, path).String()
}

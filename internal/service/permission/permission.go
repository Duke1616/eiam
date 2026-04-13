package permission

import (
	"context"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/Duke1616/eiam/internal/authz"
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/policy"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/casbin/casbin/v2"
	"github.com/ecodeclub/ekit/set"
	"github.com/ecodeclub/ekit/slice"
	"github.com/samber/lo"
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
	GetAuthorizedMenus(ctx context.Context, userId int64) (domain.MenuTree, error)

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
	AssignRoleToUser(ctx context.Context, userId int64, roleCode string) (bool, error)
	// AssignRoleInheritance 设置角色继承关系，让 childRole 自动拥有 parentRole 的所有能力
	AssignRoleInheritance(ctx context.Context, childRole string, parentRole string) (bool, error)
	// GetRolesForUser 获取用户的有效角色 (包含隐式继承树中所有的角色)
	GetRolesForUser(ctx context.Context, userId int64) ([]string, error)

	// AssignPolicyToUser 直接给用户绑定特定的策略
	AssignPolicyToUser(ctx context.Context, userId int64, policyCode string) (bool, error)
	// AssignPolicyToRole 给角色挂载特定的策略
	AssignPolicyToRole(ctx context.Context, roleCode, policyCode string) (bool, error)
	// GetImplicitSubjectsForUser 解析用户的有效身份图谱 (递归获取所有相关的 Role 和 Policy ID)
	GetImplicitSubjectsForUser(ctx context.Context, userId int64) ([]string, error)
}

type permissionService struct {
	enforcer    *casbin.SyncedEnforcer
	roleSvc     role.IRoleService
	resourceSvc resource.IResourceService
	permRepo    repository.IPermissionRepository
	policySvc   policy.IPolicyService
	authorizer  authz.IAuthorizer
}

func NewPermissionService(
	en *casbin.SyncedEnforcer,
	roleSvc role.IRoleService,
	policySvc policy.IPolicyService,
	resourceSvc resource.IResourceService,
	permRepo repository.IPermissionRepository,
	auth authz.IAuthorizer) IPermissionService {
	if en == nil {
		panic("权限服务初始化失败: Casbin Enforcer 为空，请检查数据库与配置文件")
	}
	return &permissionService{
		enforcer:    en,
		roleSvc:     roleSvc,
		policySvc:   policySvc,
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
	policies, err := s.getEffectivePolicies(ctx, userId)
	if err != nil {
		return false, err
	}

	// 4. OPA 裁决
	return s.authorizer.Authorize(ctx, authz.AuthInput{
		Actions:  codes,
		Resource: api.URN(),
		Policies: policies,
	})
}

// CheckPermission 针对特定 URN 的直接 Action 匹配
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

// GetAuthorizedMenus 过滤授权菜单并构建层级树
func (s *permissionService) GetAuthorizedMenus(ctx context.Context, userId int64) (domain.MenuTree, error) {
	// 1. 拉取元数据全集体
	allMenus, err := s.resourceSvc.ListAllMenus(ctx)
	if err != nil || len(allMenus) == 0 {
		return domain.MenuTree{}, err
	}

	// 2. 获取权限底数与策略池
	menuURNs := slice.Map(allMenus, func(_ int, m domain.Menu) string { return m.URN() })
	codesMap, err := s.permRepo.FindCodesByResourceURNs(ctx, menuURNs)
	if err != nil {
		return nil, err
	}

	policies, err := s.getEffectivePolicies(ctx, userId)
	if err != nil {
		return nil, err
	}

	// 3. 执行 OPA 批量裁决 (性能优化：全量菜单一次性判定)
	allowedURNs, err := s.authorizer.AuthorizeBatch(ctx, authz.AuthInput{
		BatchResources:  menuURNs,
		ResourceActions: s.buildResourceActionMap(menuURNs, codesMap),
		Policies:        policies,
	})
	if err != nil {
		return nil, err
	}

	// 4. 执行可见性过滤与拓扑恢复
	filtered := s.filterAccessibleMenus(allMenus, codesMap, allowedURNs)
	return domain.MenuList(filtered).ToTree(), nil
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
	// 1. 预处理数据
	allowedSet := set.NewMapSet[string](len(allowedURNs))
	for _, u := range allowedURNs {
		allowedSet.Add(u)
	}
	idMap := slice.ToMap(all, func(m domain.Menu) int64 { return m.ID })

	// 统计是否有子节点，用于判定公共叶子
	hasChildren := make(map[int64]bool, len(all))
	for _, m := range all {
		if m.ParentID != 0 {
			hasChildren[m.ParentID] = true
		}
	}

	// 2. 使用 Set 记录可见 ID，并执行回溯
	visible := set.NewMapSet[int64](len(all))
	for _, m := range all {
		u := m.URN()
		_, isBound := codesMap[u]
		if allowedSet.Exist(u) || (!isBound && !hasChildren[m.ID]) {
			for id := m.ID; id != 0 && !visible.Exist(id); id = idMap[id].ParentID {
				visible.Add(id)
			}
		}
	}

	// 3. 收集结果
	return slice.Map(visible.Keys(), func(_ int, id int64) domain.Menu {
		return idMap[id]
	})
}

// getEffectivePolicies 获取用户在当前上下文中所有有效的 Policy 对象 (含直接绑定、角色继承、系统角色收益)
func (s *permissionService) getEffectivePolicies(ctx context.Context, userId int64) ([]domain.Policy, error) {
	// 1. 获取所有隐含身份
	subjects, err := s.GetImplicitSubjectsForUser(ctx, userId)
	if err != nil {
		return nil, err
	}

	// 2. 分类 ID
	var (
		roleCodes   []string
		policyCodes []string
	)
	for _, sub := range subjects {
		subject := domain.ParseSubject(sub)
		switch subject.Type {
		case domain.SubjectTypeRole:
			roleCodes = append(roleCodes, subject.ID)
		case domain.SubjectTypePolicy:
			policyCodes = append(policyCodes, subject.ID)
		}
	}

	// 3. 并行加载详情
	return s.loadDetailedPolicies(ctx, roleCodes, policyCodes)
}

func (s *permissionService) loadDetailedPolicies(ctx context.Context, roleCodes, policyCodes []string) ([]domain.Policy, error) {
	var (
		inlinePolicies   []domain.Policy
		attachedPolicies []domain.Policy
		directPolicies   []domain.Policy
		eg               errgroup.Group
	)

	// 1. 获取角色的内联策略
	eg.Go(func() error {
		roles, err := s.roleSvc.ListByIncludeCodes(ctx, roleCodes)
		if err != nil {
			return err
		}
		for _, r := range roles {
			inlinePolicies = append(inlinePolicies, r.InlinePolicies...)
		}
		return nil
	})

	// 2. 获取角色挂载的托管策略
	eg.Go(func() error {
		roleMap, err := s.policySvc.GetAttachedPoliciesByCodes(ctx, roleCodes)
		if err != nil {
			return err
		}
		for _, ps := range roleMap {
			attachedPolicies = append(attachedPolicies, ps...)
		}
		return nil
	})

	// 3. 获取直接绑定的策略
	eg.Go(func() error {
		var err error
		directPolicies, err = s.policySvc.ListByCodes(ctx, policyCodes)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	// 4. 合并所有策略并去重
	allPolicies := append(inlinePolicies, attachedPolicies...)
	allPolicies = append(allPolicies, directPolicies...)
	return lo.UniqBy(allPolicies, func(p domain.Policy) string { return p.Code }), nil
}

func (s *permissionService) CreatePermission(ctx context.Context, p domain.Permission) (int64, error) {
	return s.permRepo.CreatePermission(ctx, p)
}

func (s *permissionService) GetByCode(ctx context.Context, code string) (domain.Permission, error) {
	return s.permRepo.GetByCode(ctx, code)
}

func (s *permissionService) GetPermissionManifest(ctx context.Context) (domain.PermissionManifest, error) {
	var (
		perms    []domain.Permission
		svcMetas []domain.Service
		eg       errgroup.Group
	)

	// 1. 并行抓取权限底数与服务元数据
	eg.Go(func() error {
		var err error
		perms, err = s.permRepo.ListAllPermissions(ctx)
		return err
	})

	eg.Go(func() error {
		var err error
		svcMetas, err = s.resourceSvc.ListServices(ctx)
		return err
	})

	if err := eg.Wait(); err != nil {
		return domain.PermissionManifest{}, err
	}

	// 2. 构建基础索引
	svcMap := slice.ToMap(svcMetas, func(s domain.Service) string { return s.Code })

	// 3. 链式逻辑变换：按 Service -> Group 维度进行二级聚合
	svcGroups := lo.GroupBy(perms, func(p domain.Permission) string { return p.Service })

	serviceNodes := lo.MapToSlice(svcGroups, func(svcCode string, permsInSvc []domain.Permission) domain.ServiceNode {
		// 二级聚合：按 Group 维度
		gGroups := lo.GroupBy(permsInSvc, func(p domain.Permission) string { return p.Group })

		// 补全服务显示名称
		svcName := strings.ToUpper(svcCode)
		if meta, ok := svcMap[svcCode]; ok && meta.Name != "" {
			svcName = meta.Name
		}

		return domain.ServiceNode{
			Code: svcCode,
			Name: svcName,
			Groups: lo.MapToSlice(gGroups, func(gName string, gPerms []domain.Permission) domain.GroupNode {
				return domain.GroupNode{
					Name:    gName,
					Actions: lo.Map(gPerms, func(p domain.Permission, _ int) string { return p.Code }),
				}
			}),
		}
	})

	return domain.PermissionManifest{
		Permissions: perms,
		Services:    serviceNodes,
	}, nil
}

func (s *permissionService) BindResourcesToPermission(ctx context.Context, permId int64, permCode string, resURNs []string) error {
	return s.permRepo.BindResources(ctx, permId, permCode, resURNs)
}

func (s *permissionService) AssignRoleToUser(ctx context.Context, userId int64, roleCode string) (bool, error) {
	// 前置校验角色是否存在且合法
	_, err := s.roleSvc.GetByCode(ctx, roleCode)
	if err != nil {
		return false, err
	}

	tid := ctxutil.GetTenantID(ctx).String()
	return s.enforcer.AddGroupingPolicy(
		domain.UserSubject(userId),
		domain.RoleSubject(roleCode),
		tid,
	)
}

func (s *permissionService) AssignRoleInheritance(ctx context.Context, childRole string, parentRole string) (bool, error) {
	// 双重验证，严禁为不存在的角色创建继承关系
	if _, err := s.roleSvc.GetByCode(ctx, childRole); err != nil {
		return false, err
	}
	if _, err := s.roleSvc.GetByCode(ctx, parentRole); err != nil {
		return false, err
	}

	tid := ctxutil.GetTenantID(ctx).String()
	// 环路检测 (基于马甲标识)
	childSub := domain.RoleSubject(childRole)
	parentSub := domain.RoleSubject(parentRole)

	ancestors, err := s.enforcer.GetImplicitRolesForUser(parentSub, tid)
	if err != nil {
		return false, err
	}

	for _, ancestor := range ancestors {
		if ancestor == childSub {
			return false, errs.ErrRoleCycleInheritance
		}
	}

	return s.enforcer.AddGroupingPolicy(childSub, parentSub, tid)
}

func (s *permissionService) GetRolesForUser(ctx context.Context, userId int64) ([]string, error) {
	subjects, err := s.GetImplicitSubjectsForUser(ctx, userId)
	if err != nil {
		return nil, err
	}

	// 提取角色标识码
	return lo.FilterMap(subjects, func(item string, _ int) (string, bool) {
		sub := domain.ParseSubject(item)
		if sub.Type == domain.SubjectTypeRole {
			return sub.ID, true
		}
		return "", false
	}), nil
}

func (s *permissionService) AssignPolicyToUser(ctx context.Context, userId int64, policyCode string) (bool, error) {
	tid := ctxutil.GetTenantID(ctx).String()
	return s.enforcer.AddGroupingPolicy(
		domain.UserSubject(userId),
		domain.PolicySubject(policyCode),
		tid,
	)
}

func (s *permissionService) AssignPolicyToRole(ctx context.Context, roleCode, policyCode string) (bool, error) {
	tid := ctxutil.GetTenantID(ctx).String()
	return s.enforcer.AddGroupingPolicy(
		domain.RoleSubject(roleCode),
		domain.PolicySubject(policyCode),
		tid,
	)
}

func (s *permissionService) GetImplicitSubjectsForUser(ctx context.Context, userId int64) ([]string, error) {
	tid := ctxutil.GetTenantID(ctx).String()
	return s.enforcer.GetImplicitRolesForUser(domain.UserSubject(userId), tid)
}

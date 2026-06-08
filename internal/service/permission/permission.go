package permission

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Duke1616/eiam/internal/pkg/searcher"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/internal/service/permission/checker"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/ecodeclub/ekit/set"
	"golang.org/x/sync/errgroup"

	"github.com/Duke1616/eiam/internal/authz"
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/policy"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/casbin/casbin/v2"
	"github.com/ecodeclub/ekit/slice"
	"github.com/samber/lo"
)

var (
	// actionPriorityRules 预编译动作优先级正则，提升排序性能
	actionPriorityRules = []struct {
		pattern *regexp.Regexp
		weight  int
	}{
		{pattern: regexp.MustCompile(`^(view|list|get|manifest|show).*`), weight: 100},
		{pattern: regexp.MustCompile(`^(add|create|save|new).*`), weight: 90},
		{pattern: regexp.MustCompile(`^(edit|update|modify|toggle|change).*`), weight: 80},
		{pattern: regexp.MustCompile(`^(delete|revoke|remove|drop).*`), weight: 70},
	}
)

type permissionService struct {
	enforcer    *casbin.SyncedEnforcer
	resourceSvc resource.IResourceService
	roleSvc     role.IRoleService
	permRepo    repository.IPermissionRepository
	policySvc   policy.IPolicyService
	authorizer  authz.IAuthorizer

	// registry 注册中心 (组合模式处理：全域搜索与计数聚合)
	registry searcher.ISubjectRegistry
	boundary checker.IBoundaryChecker
}

func NewPermissionService(
	en *casbin.SyncedEnforcer,
	policySvc policy.IPolicyService,
	roleSvc role.IRoleService,
	registry searcher.ISubjectRegistry,
	resourceSvc resource.IResourceService,
	permRepo repository.IPermissionRepository,
	auth authz.IAuthorizer,
	boundary checker.IBoundaryChecker) IPermissionService {
	if en == nil {
		panic("权限服务初始化失败: Casbin Enforcer 为空，请检查数据库与配置文件")
	}

	return &permissionService{
		enforcer:    en,
		policySvc:   policySvc,
		roleSvc:     roleSvc,
		registry:    registry,
		resourceSvc: resourceSvc,
		permRepo:    permRepo,
		authorizer:  auth,
		boundary:    boundary,
	}
}

func (s *permissionService) SearchSubjects(ctx context.Context, keyword string, subType string, offset, limit int64) ([]domain.Subject, int64, error) {
	// 委托给注册中心处理路由与聚合
	p := s.registry.Route(subType)

	var (
		total    int64
		subjects []searcher.Subject
		eg       errgroup.Group
	)

	// 并行执行计数与搜索，两者互不依赖
	eg.Go(func() error {
		var err error
		total, err = p.CountSubjects(ctx, keyword)
		return err
	})
	eg.Go(func() error {
		var err error
		subjects, err = p.SearchSubjects(ctx, keyword, offset, limit)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, 0, err
	}

	return slice.Map(subjects, func(idx int, src searcher.Subject) domain.Subject {
		return domain.Subject{Type: src.Type, ID: src.ID, Name: src.Name, Desc: src.Desc}
	}), total, nil
}

// CheckAPI 针对物理接口访问进行判定
func (s *permissionService) CheckAPI(ctx context.Context, username string, serviceName, method, path string) (bool, error) {
	// 1. 资产发现
	api, err := s.resourceSvc.FindAPIByPath(ctx, serviceName, method, path)
	if err != nil {
		return false, fmt.Errorf("查询接口资产失败: %w", err)
	}
	if api.ID == 0 {
		// Fail-closed: 未注册资产直接拒绝，不暴露资产缺失细节
		return false, nil
	}

	// 2. 映射发现 (找到该接口绑定的逻辑权限码)
	urn := api.URN()
	targetCodes, err := s.permRepo.FindCodesByResource(ctx, urn)
	if err != nil {
		return false, fmt.Errorf("查询接口映射错误: %w", err)
	}

	// 3. 放行逻辑：未绑定权限代码的资源视为公共资产，仅需登录即可访问
	if len(targetCodes) == 0 {
		return true, nil
	}

	// 4. 边界拦截：普通租户严禁访问系统级权限点
	if err = s.boundary.ValidateActionScopes(ctx, targetCodes); err != nil {
		return false, err
	}

	// 5. 权限依赖展开 (核心逻辑：检查父节点)
	// 从数据库反向查找哪些权限码依赖了当前接口要求的 targetCodes
	candidateActions, err := s.expandParentActionsFromDB(ctx, targetCodes)
	if err != nil {
		return false, err
	}

	// 6. 业务鉴权：执行精准的 OPA 策略判定
	policies, err := s.getEffectivePolicies(ctx, username)
	if err != nil {
		return false, err
	}

	return s.authorizer.Authorize(ctx, authz.AuthInput{
		Actions:  candidateActions,
		Resource: urn,
		Policies: policies,
	})
}

// expandParentActionsFromDB 通过数据库反向查询，将目标权限码展开为其所有的“上级权限码”
func (s *permissionService) expandParentActionsFromDB(ctx context.Context, targetCodes []string) ([]string, error) {
	// 1. 获取依赖于 targetCodes 的父级权限码
	parents, err := s.permRepo.FindParentsByNeeds(ctx, targetCodes)
	if err != nil {
		return nil, err
	}

	// 2. 合并并去重
	actionSet := set.NewMapSet[string](len(targetCodes) + len(parents))
	for _, code := range targetCodes {
		actionSet.Add(code)
	}
	for _, p := range parents {
		actionSet.Add(p)
	}

	return actionSet.Keys(), nil
}

// CheckPermission 针对特定 URN 的直接 Action 匹配
func (s *permissionService) CheckPermission(ctx context.Context, username string, action, resourceURN string) (bool, error) {
	policies, err := s.getEffectivePolicies(ctx, username)
	if err != nil {
		return false, err
	}

	return s.authorizer.Authorize(ctx, authz.AuthInput{
		Actions:  []string{action},
		Resource: resourceURN,
		Policies: policies,
	})
}

// GetAuthorizedCodes 获取用户拥有的所有逻辑权限代码 (走 OPA 批量裁决)
func (s *permissionService) GetAuthorizedCodes(ctx context.Context, username string) ([]string, error) {
	// 1. 获取全量可见清单 (已处理租户边界)
	manifest, err := s.GetPermissionManifest(ctx)
	if err != nil {
		return nil, err
	}

	// 2. 准备判定参数
	allCodes := lo.Map(manifest.Permissions, func(p domain.Permission, _ int) string {
		return p.Code
	})

	// 3. 获取用户策略
	policies, err := s.getEffectivePolicies(ctx, username)
	if err != nil {
		return nil, err
	}

	// 4. 执行 OPA 批量裁决
	// 策略：我们将每一个权限码（Code）伪装成一个资源（Resource）进行判定
	// OPA 的 AuthorizeBatch 会返回所有“允许访问”的资源名，这些资源名刚好就是我们要的权限码
	resourceActions := make(map[string][]string, len(allCodes))
	for _, code := range allCodes {
		resourceActions[code] = []string{code}
	}

	return s.authorizer.AuthorizeBatch(ctx, authz.AuthInput{
		BatchResources:  allCodes,
		ResourceActions: resourceActions,
		Policies:        policies,
	})
}

// GetAuthorizedMenus 过滤授权菜单并构建层级树
func (s *permissionService) GetAuthorizedMenus(ctx context.Context, username string) (domain.MenuTree, error) {
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

	// 3. 边界预过滤：非系统租户剔除掉所有包含 ScopeSystem 权限的菜单 URN
	if menuURNs, err = s.filterByBoundary(ctx, menuURNs, codesMap); err != nil {
		return nil, err
	}

	policies, err := s.getEffectivePolicies(ctx, username)
	if err != nil {
		return nil, err
	}

	// 4. 执行 OPA 批量裁决 (性能优化：全量菜单一次性判定)
	allowedURNs, err := s.authorizer.AuthorizeBatch(ctx, authz.AuthInput{
		BatchResources:  menuURNs,
		ResourceActions: s.buildResourceActionMap(menuURNs, codesMap),
		Policies:        policies,
	})
	if err != nil {
		return nil, err
	}

	// 5. 执行可见性过滤与拓扑恢复
	filtered := s.filterAccessibleMenus(allMenus, codesMap, allowedURNs)
	return domain.MenuList(filtered).ToTree(), nil
}

// filterByBoundary 根据系统边界定义，剔除当前租户无权查看的 URN 列表
func (s *permissionService) filterByBoundary(ctx context.Context, urns []string, codesMap map[string][]string) ([]string, error) {
	if ctxutil.GetTenantID(ctx).Int64() == ctxutil.SystemTenantID || len(urns) == 0 {
		return urns, nil
	}

	// 1. 批量识别哪些动作代码属于“系统级受限”
	allCodes := lo.Uniq(lo.Flatten(lo.Values(codesMap)))
	forbidden, err := s.boundary.GetForbiddenActions(ctx, allCodes)
	if err != nil || len(forbidden) == 0 {
		return urns, err
	}

	// 2. 内存级快速过滤
	forbiddenSet := set.NewMapSet[string](len(forbidden))
	for _, fc := range forbidden {
		forbiddenSet.Add(fc)
	}

	return lo.Filter(urns, func(u string, _ int) bool {
		return !slice.ContainsFunc(codesMap[u], forbiddenSet.Exist)
	}), nil
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
func (s *permissionService) getEffectivePolicies(ctx context.Context, username string) ([]domain.Policy, error) {
	// 【核心优化】：身份对齐
	// 权限判定应当基于用户的“原始身份租户 (Origin)”而非“操作目标租户 (Target)”
	authTid := ctxutil.GetOriginTenantID(ctx)
	if authTid != 0 {
		ctx = ctxutil.WithTenantID(ctx, authTid.Int64())
	}

	// 1. 获取用户的所有角色（包括继承）
	roleSubjects, err := s.GetRolesForUser(ctx, username)
	if err != nil {
		return nil, err
	}

	// 去除角色前缀，获取纯角色代码
	roleCodes := lo.Map(roleSubjects, func(subject string, _ int) string {
		return strings.TrimPrefix(subject, domain.PrefixRole)
	})

	// 2. 构建主体：用户和所有角色
	subjects := []domain.Subject{
		{Type: domain.SubjectTypeUser, ID: username},
	}
	for _, code := range roleCodes {
		subjects = append(subjects, domain.Subject{Type: domain.SubjectTypeRole, ID: code})
	}

	// 3. 获取所有主体的策略
	policiesMap, err := s.policySvc.GetAttachedBySubjects(ctx, subjects)
	if err != nil {
		return nil, err
	}

	// 4. 获取角色的内联策略
	roles, err := s.roleSvc.ListByIncludeCodes(ctx, roleCodes)
	if err != nil {
		return nil, err
	}

	var inlinePolicies []domain.Policy
	for _, r := range roles {
		inlinePolicies = append(inlinePolicies, r.InlinePolicies...)
	}

	// 5. 合并所有策略
	var allPolicies []domain.Policy
	for _, ps := range policiesMap {
		allPolicies = append(allPolicies, ps...)
	}
	allPolicies = append(allPolicies, inlinePolicies...)

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

	// 2. 数据预处理
	perms = s.filterByScope(ctx, perms)
	svcMap := slice.ToMap(svcMetas, func(s domain.Service) string { return s.Code })

	// 3. 构建资产树
	serviceNodes := s.toServiceNodes(perms, svcMap)

	return domain.PermissionManifest{
		Permissions: perms,
		Services:    serviceNodes,
	}, nil
}

// filterByScope 租户隔离过滤
func (s *permissionService) filterByScope(ctx context.Context, perms []domain.Permission) []domain.Permission {
	if ctxutil.GetTenantID(ctx).Int64() == ctxutil.SystemTenantID {
		return perms
	}
	return lo.Filter(perms, func(p domain.Permission, _ int) bool {
		return p.Scope == domain.ScopeTenant
	})
}

// toServiceNodes 核心变换逻辑：按 Service -> Group 聚合
func (s *permissionService) toServiceNodes(perms []domain.Permission, svcMap map[string]domain.Service) []domain.ServiceNode {
	svcGroups := lo.GroupBy(perms, func(p domain.Permission) string { return p.Service })

	nodes := lo.MapToSlice(svcGroups, func(svcCode string, permsInSvc []domain.Permission) domain.ServiceNode {
		svcName := strings.ToUpper(svcCode)
		if meta, ok := svcMap[svcCode]; ok && meta.Name != "" {
			svcName = meta.Name
		}

		return domain.ServiceNode{
			Code:   svcCode,
			Name:   svcName,
			Groups: s.buildGroupNodes(permsInSvc),
		}
	})

	// 服务层级排序
	slices.SortFunc(nodes, func(a, b domain.ServiceNode) int {
		return strings.Compare(a.Code, b.Code)
	})
	return nodes
}

// buildGroupNodes 分组树形组装逻辑
func (s *permissionService) buildGroupNodes(perms []domain.Permission) []domain.GroupNode {
	root := newGroupTrie("")

	for _, p := range perms {
		parts := strings.Split(p.Group, "/")
		root.insert(parts, p.Code)
	}

	return root.toGroupNodes(s.sortActions)
}

// groupTrie 权限分组辅助字典树
type groupTrie struct {
	name     string
	actions  []string
	children map[string]*groupTrie
}

func newGroupTrie(name string) *groupTrie {
	return &groupTrie{
		name:     name,
		children: make(map[string]*groupTrie),
	}
}

func (t *groupTrie) insert(path []string, action string) {
	curr := t
	for _, part := range path {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, exists := curr.children[part]; !exists {
			curr.children[part] = newGroupTrie(part)
		}
		curr = curr.children[part]
	}
	curr.actions = append(curr.actions, action)
}

func (t *groupTrie) toGroupNodes(sortActions func([]string)) []domain.GroupNode {
	if len(t.children) == 0 {
		return nil
	}

	nodes := make([]domain.GroupNode, 0, len(t.children))
	for _, child := range t.children {
		sortActions(child.actions)
		nodes = append(nodes, domain.GroupNode{
			Name:     child.name,
			Actions:  child.actions,
			Children: child.toGroupNodes(sortActions),
		})
	}

	slices.SortFunc(nodes, func(a, b domain.GroupNode) int {
		return strings.Compare(a.Name, b.Name)
	})
	return nodes
}

// sortActions 动作权重排序算法 (支持正则匹配)
func (s *permissionService) sortActions(actions []string) {
	// 定义正则优先级规则 (按顺序匹配，命中即止)
	type rule struct {
		pattern *regexp.Regexp
		weight  int
	}

	rules := []rule{
		{pattern: regexp.MustCompile(`^(view|list|get|manifest|show).*`), weight: 100},
		{pattern: regexp.MustCompile(`^(add|create|save|new).*`), weight: 90},
		{pattern: regexp.MustCompile(`^(edit|update|modify|toggle|change).*`), weight: 80},
		{pattern: regexp.MustCompile(`^(delete|revoke|remove|drop).*`), weight: 70},
	}

	priority := func(code string) int {
		parts := strings.Split(code, ":")
		action := parts[len(parts)-1]

		for _, r := range rules {
			if r.pattern.MatchString(action) {
				return r.weight
			}
		}
		return 0
	}

	slices.SortFunc(actions, func(a, b string) int {
		pa, pb := priority(a), priority(b)
		if pa != pb {
			return pb - pa
		}
		return strings.Compare(a, b)
	})
}

func (s *permissionService) BindResourcesToPermission(ctx context.Context, permId int64, permCode string, resURNs []string) error {
	sysCtx := ctxutil.WithTenantID(ctx, ctxutil.SystemTenantID)
	return s.permRepo.BindResources(sysCtx, permId, permCode, resURNs)
}

func (s *permissionService) AssignRoleToUser(ctx context.Context, username string, roleCode string) (bool, error) {
	return s.AssignRolesToUser(ctx, []string{username}, []string{roleCode})
}

func (s *permissionService) AssignRolesToUser(ctx context.Context, usernames []string, roleCodes []string) (bool, error) {
	if len(usernames) == 0 || len(roleCodes) == 0 {
		return true, nil
	}

	// 1. 批量校验角色合法性
	if _, err := s.roleSvc.ListByIncludeCodes(ctx, roleCodes); err != nil {
		return false, err
	}

	tid := ctxutil.GetTenantID(ctx).String()

	// 2. 获取当前租户下已有的所有关系，用于在内存中去重
	// GetFilteredGroupingPolicy(2, tid) 表示匹配 v2 (TenantID)
	existingRules, _ := s.enforcer.GetFilteredGroupingPolicy(2, tid)
	existingSet := lo.SliceToMap(existingRules, func(r []string) (string, struct{}) {
		// 按 "Subject:Object" 构建唯一标识
		return r[0] + ":" + r[1], struct{}{}
	})

	// 3. 构造 Casbin 批量规则 (笛卡尔积: User x Role) 并过滤掉已存在的
	now := strconv.FormatInt(time.Now().UnixMilli(), 10)
	rules := lo.FlatMap(usernames, func(username string, _ int) [][]string {
		return lo.FilterMap(roleCodes, func(rc string, _ int) ([]string, bool) {
			sub := domain.UserSubject(username)
			obj := domain.RoleSubject(rc)

			// 如果该 "用户-角色" 关联已存在，则跳过，防止重复绑定
			if _, ok := existingSet[sub+":"+obj]; ok {
				return nil, false
			}

			return []string{sub, obj, tid, now}, true
		})
	})

	if len(rules) == 0 {
		return true, nil
	}

	return s.enforcer.AddGroupingPolicies(rules)
}

func (s *permissionService) AssignUsersToRole(ctx context.Context, roleCode string, usernames []string) (bool, error) {
	return s.AssignRolesToUser(ctx, usernames, []string{roleCode})
}

func (s *permissionService) RemoveRoleFromUser(ctx context.Context, username string, roleCode string) (bool, error) {
	return s.RemoveRolesFromUser(ctx, []string{username}, []string{roleCode})
}

func (s *permissionService) RemoveRolesFromUser(ctx context.Context, usernames []string, roleCodes []string) (bool, error) {
	if len(usernames) == 0 || len(roleCodes) == 0 {
		return true, nil
	}

	tid := ctxutil.GetTenantID(ctx).String()

	// 1. 获取该租户下的所有关联规则，以获取包含 v3 (时间戳) 的完整规则
	existingRules, _ := s.enforcer.GetFilteredGroupingPolicy(2, tid)

	// 2. 构造待删除的匹配集合
	userSubjects := lo.SliceToMap(usernames, func(u string) (string, struct{}) {
		return domain.UserSubject(u), struct{}{}
	})
	roleSubjects := lo.SliceToMap(roleCodes, func(rc string) (string, struct{}) {
		return domain.RoleSubject(rc), struct{}{}
	})

	// 3. 从现有规则中筛选出匹配的完整规则 (必须 4 列全匹配才能删除)
	rulesToRemove := lo.Filter(existingRules, func(r []string, _ int) bool {
		if len(r) < 2 {
			return false
		}
		_, okUser := userSubjects[r[0]]
		_, okRole := roleSubjects[r[1]]
		return okUser && okRole
	})

	if len(rulesToRemove) == 0 {
		return true, nil
	}

	return s.enforcer.RemoveGroupingPolicies(rulesToRemove)
}

func (s *permissionService) AddRoleInheritance(ctx context.Context, roleCode string, parentRoleCode string) (bool, error) {
	// 1. 基础校验：严禁自继承
	if roleCode == parentRoleCode {
		return false, errs.ErrRoleSelfInheritance
	}

	// 2. 验证角色合法性，严禁为不存在的角色创建继承关系
	if _, err := s.roleSvc.GetByCode(ctx, roleCode); err != nil {
		return false, err
	}
	if _, err := s.roleSvc.GetByCode(ctx, parentRoleCode); err != nil {
		return false, err
	}

	tid := ctxutil.GetTenantID(ctx).String()
	childSub := domain.RoleSubject(roleCode)
	parentSub := domain.RoleSubject(parentRoleCode)

	// 2. 环路检测：防止 A 继承 B，而 B 已经是 A 的子角色
	ancestors, err := s.enforcer.GetImplicitRolesForUser(parentSub, tid)
	if err != nil {
		return false, err
	}
	for _, ancestor := range ancestors {
		if ancestor == childSub {
			return false, errs.ErrRoleCycleInheritance
		}
	}

	return s.enforcer.AddGroupingPolicy(childSub, parentSub, tid, strconv.FormatInt(time.Now().UnixMilli(), 10))
}

func (s *permissionService) RemoveRoleInheritance(ctx context.Context, roleCode string, parentRoleCode string) (bool, error) {
	// 1. 获取角色详情以核实类型
	child, err := s.roleSvc.GetByCode(ctx, roleCode)
	if err != nil {
		return false, err
	}
	parent, err := s.roleSvc.GetByCode(ctx, parentRoleCode)
	if err != nil {
		return false, err
	}

	// 2. 强校验：如果两者都是系统预设角色，则严禁移除关系
	if child.Type == domain.RoleTypeSystem && parent.Type == domain.RoleTypeSystem {
		return false, errs.ErrImmutableInheritance
	}

	tid := ctxutil.GetTenantID(ctx).String()
	childSub := domain.RoleSubject(roleCode)
	parentSub := domain.RoleSubject(parentRoleCode)

	// 3. 获取该租户下的所有关联规则，以获取包含 v3 (时间戳) 的完整规则
	existingRules, _ := s.enforcer.GetFilteredGroupingPolicy(2, tid)

	// 4. 筛选出匹配的完整规则 (必须 4 列全匹配才能删除)
	rulesToRemove := lo.Filter(existingRules, func(r []string, _ int) bool {
		return len(r) >= 2 && r[0] == childSub && r[1] == parentSub
	})

	if len(rulesToRemove) == 0 {
		return true, nil
	}

	return s.enforcer.RemoveGroupingPolicies(rulesToRemove)
}

func (s *permissionService) GetParentRoles(ctx context.Context, roleCode string) ([]domain.InheritanceInfo, error) {
	tid := ctxutil.GetTenantID(ctx).String()
	sub := domain.RoleSubject(roleCode)

	// 查询本角色详情以获取其类型
	currentRole, err := s.roleSvc.GetByCode(ctx, roleCode)
	if err != nil {
		return nil, err
	}

	// 1. 获取直接直接父角色 (第一层)
	directParents, err := s.enforcer.GetRolesForUser(sub, tid)
	if err != nil {
		return nil, err
	}
	directMap := lo.SliceToMap(directParents, func(item string) (string, bool) {
		return item, true
	})

	// 2. 获取隐含的所有父角色 (递归全量)
	allParents, err := s.enforcer.GetImplicitRolesForUser(sub, tid)
	if err != nil {
		return nil, err
	}

	// 提前拉取所有父角色的详细信息，用于判定 Type
	parentCodes := lo.Map(allParents, func(p string, _ int) string {
		return domain.ExtractRoleCode(p)
	})
	parentTypeMap := make(map[string]uint8)
	for _, pc := range parentCodes {
		if pr, err := s.roleSvc.GetByCode(ctx, pc); err == nil {
			parentTypeMap[pc] = pr.Type
		}
	}

	// 3. 组装并去重
	var infos []domain.InheritanceInfo
	seen := make(map[string]bool)
	for _, p := range allParents {
		if p == sub || seen[p] {
			continue
		}
		seen[p] = true
		pc := domain.ExtractRoleCode(p)

		// 判定逻辑：如果本角色和父角色都是系统角色 (Type=1)，则标记为不可变
		isImmutable := currentRole.Type == domain.RoleTypeSystem && parentTypeMap[pc] == domain.RoleTypeSystem

		infos = append(infos, domain.InheritanceInfo{
			Code:        pc,
			IsDirect:    directMap[p],
			IsImmutable: isImmutable,
		})
	}

	return infos, nil
}

// GetRolesForUser 获取用户当前拥有的所有角色清单 (含继承关系)
func (s *permissionService) GetRolesForUser(ctx context.Context, username string) ([]string, error) {
	tid := ctxutil.GetTenantID(ctx).String()

	roles, err := s.enforcer.GetImplicitRolesForUser(domain.UserSubject(username), tid)
	if err != nil {
		return nil, err
	}

	return lo.Uniq(roles), nil
}

func (s *permissionService) AssignPolicyToUser(ctx context.Context, username string, policyCode string) error {
	return s.policySvc.AttachPolicyToUser(ctx, username, policyCode)
}

func (s *permissionService) AssignPolicyToRole(ctx context.Context, roleCode, policyCode string) error {
	return s.policySvc.AttachPolicyToRole(ctx, roleCode, policyCode)
}

func (s *permissionService) GetImplicitSubjectsForUser(ctx context.Context, username string) ([]string, error) {
	roles, err := s.GetRolesForUser(ctx, username)
	if err != nil {
		return nil, err
	}
	return lo.Map(roles, func(role string, _ int) string {
		return domain.RoleSubject(role)
	}), nil
}

func (s *permissionService) ListAuthorizations(ctx context.Context, query domain.AuthorizationQuery) ([]domain.Authorization, int64, error) {
	// 定义所有授权提供者
	providers := []AuthorizationProvider{
		&roleAuthorizationProvider{service: s},
		&policyAuthorizationProvider{service: s},
	}

	// 如果指定了 ObjType，直接查询对应类型
	if query.ObjType != "" {
		for _, provider := range providers {
			if provider.ObjType() == query.ObjType {
				return provider.ListAuthorizations(ctx, query)
			}
		}
		// 处理 AuthObjCustomPolicy 的情况，它也使用策略提供者
		if query.ObjType == domain.AuthObjCustomPolicy {
			for _, provider := range providers {
				if provider.ObjType() == domain.AuthObjSystemPolicy {
					return provider.ListAuthorizations(ctx, query)
				}
			}
		}
		return []domain.Authorization{}, 0, nil
	}

	// 查询所有类型，使用统一的聚合逻辑
	return s.aggregateAuthorizations(ctx, providers, query)
}

// aggregateAuthorizations 聚合多个提供者的查询结果
func (s *permissionService) aggregateAuthorizations(ctx context.Context, providers []AuthorizationProvider, query domain.AuthorizationQuery) ([]domain.Authorization, int64, error) {
	if len(providers) == 0 {
		return []domain.Authorization{}, 0, nil
	}

	// 单提供者直接查询
	if len(providers) == 1 {
		return providers[0].ListAuthorizations(ctx, query)
	}

	// 多提供者需要分别查询并聚合
	var (
		allAuths []domain.Authorization
		total    int64
	)

	for _, provider := range providers {
		auths, count, err := provider.ListAuthorizations(ctx, query)
		if err != nil {
			return nil, 0, err
		}
		allAuths = append(allAuths, auths...)
		total += count
	}

	return allAuths, total, nil
}

func (s *permissionService) listRoleAuthorizations(ctx context.Context, query domain.AuthorizationQuery) ([]domain.Authorization, int64, error) {
	var v0Prefix, v1Prefix string

	// 映射主体筛选前缀
	if query.SubType != "" {
		v0Prefix = query.SubType.Prefix()
	}

	v1Prefix = domain.PrefixRole

	tid := ctxutil.GetTenantID(ctx).Int64()
	// 分页拉取原子规则记录
	rules, total, err := s.permRepo.ListCasbinRules(ctx, tid, query.Offset, query.Limit, v0Prefix, v1Prefix, query.Keyword)
	if err != nil {
		return nil, 0, err
	}

	// 核心流水线：转换 -> 回填
	authorizations := s.toAuthorizations(rules)
	if err = s.hydrateMetadata(ctx, rules, authorizations); err != nil {
		return nil, 0, err
	}

	return authorizations, total, nil
}

func (s *permissionService) listPolicyAuthorizations(ctx context.Context, query domain.AuthorizationQuery) ([]domain.Authorization, int64, error) {
	var subType string

	// 映射主体类型
	if query.SubType != "" {
		subType = query.SubType.SubjectType()
	}

	// 策略类型
	var policyType uint8 = 0
	if query.ObjType != "" {
		policyType = query.ObjType.PolicyType()
	}

	// 获取策略分配
	assignments, total, err := s.policySvc.ListAssignments(ctx, query.Offset, query.Limit, subType, query.Keyword, policyType)
	if err != nil {
		return nil, 0, err
	}

	// 转换到 Authorization
	authorizations := make([]domain.Authorization, 0, len(assignments))
	for _, a := range assignments {
		var subject domain.Subject
		switch a.SubType {
		case domain.SubjectTypeUser:
			subject = domain.Subject{Type: domain.SubjectTypeUser, ID: a.SubCode}
		case domain.SubjectTypeRole:
			subject = domain.Subject{Type: domain.SubjectTypeRole, ID: a.SubCode}
		default:
			// 处理未知类型的情况
			subject = domain.Subject{Type: a.SubType, ID: a.SubCode}
		}
		target := domain.Subject{Type: domain.SubjectTypePolicy, ID: a.PolicyCode}
		authorizations = append(authorizations, domain.Authorization{
			ID:      a.Id,
			Subject: subject,
			Target:  target,
			Ctime:   a.Ctime,
		})
	}

	// 回填元数据
	if err = s.hydratePolicyMetadata(ctx, assignments, authorizations); err != nil {
		return nil, 0, err
	}

	return authorizations, total, nil
}

// toAuthorizations 将规则原始模型转换为初步领域对象
func (s *permissionService) toAuthorizations(rules []dao.CasbinRule) []domain.Authorization {
	return slice.Map(rules, func(i int, rule dao.CasbinRule) domain.Authorization {
		return domain.Authorization{
			ID:      rule.ID,
			Subject: domain.ParseSubject(rule.V0),
			Target:  domain.ParseSubject(rule.V1),
		}
	})
}

func (s *permissionService) hydrateMetadata(ctx context.Context, rules []dao.CasbinRule, auths []domain.Authorization) error {
	// 1. 收集所有 URN (如 user:xxx, role:xxx)
	urns := make([]string, 0, len(rules)*2)
	for _, r := range rules {
		urns = append(urns, r.V0, r.V1)
	}

	// 2. 并行拉取并构建元数据图谱 (使用 lo.Uniq 去重)
	metaMap, err := s.fetchMetadataMap(ctx, lo.Uniq(urns))
	if err != nil {
		return err
	}

	// 3. 原子化回填：将 ID 翻译为展示名和备注
	for i := range auths {
		auth := &auths[i]
		v0Meta := metaMap[rules[i].V0]
		v1Meta := metaMap[rules[i].V1]

		// 调用领域层治理逻辑
		auth.FormatGovernance(v0Meta, v1Meta)
	}
	return nil
}

func (s *permissionService) fetchMetadataMap(ctx context.Context, urns []string) (map[string]domain.EntityMetadata, error) {
	var (
		eg        errgroup.Group
		roleCodes []string
		mu        sync.Mutex // 保护映射表并发写入
		metaMap   = make(map[string]domain.EntityMetadata)
	)

	// 分类
	for _, urn := range urns {
		if strings.HasPrefix(urn, domain.PrefixRole) {
			roleCodes = append(roleCodes, strings.TrimPrefix(urn, domain.PrefixRole))
		}
	}

	// 并行回填
	eg.Go(func() error {
		rs, err := s.roleSvc.ListByIncludeCodes(ctx, lo.Uniq(roleCodes))
		if err != nil {
			return err
		}

		mu.Lock()
		defer mu.Unlock()
		for _, r := range rs {
			metaMap[domain.RoleSubject(r.Code)] = domain.EntityMetadata{Name: r.Name, Desc: "角色继承关系"}
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	return metaMap, nil
}

func (s *permissionService) hydratePolicyMetadata(ctx context.Context, assignments []dao.PolicyAssignment, auths []domain.Authorization) error {
	// 收集所有策略代码
	policyCodes := make([]string, 0, len(assignments))
	for _, a := range assignments {
		policyCodes = append(policyCodes, a.PolicyCode)
	}

	// 获取策略元数据
	ps, err := s.policySvc.ListByCodes(ctx, lo.Uniq(policyCodes))
	if err != nil {
		return err
	}

	metaMap := make(map[string]domain.EntityMetadata)
	for _, p := range ps {
		metaMap[p.Code] = domain.EntityMetadata{Name: p.Name, Desc: p.Desc, Type: uint8(p.Type)}
	}

	// 回填
	for i := range auths {
		auth := &auths[i]
		v1Meta := metaMap[auth.Target.ID]
		auth.FormatGovernance(domain.EntityMetadata{}, v1Meta) // 主体元数据为空，因为我们知道类型
	}
	return nil
}

func (s *permissionService) GetPolicySummary(ctx context.Context, p domain.Policy) (domain.PolicySummary, error) {
	// 针对单条策略，复用批量逻辑以保持行为一致且易于维护
	res, err := s.GetPoliciesSummary(ctx, []domain.Policy{p})
	if err != nil {
		return domain.PolicySummary{}, err
	}
	if len(res) == 0 {
		return domain.PolicySummary{}, nil
	}
	return res[0], nil
}

func (s *permissionService) GetPoliciesSummary(ctx context.Context, policies []domain.Policy) ([]domain.PolicySummary, error) {
	if len(policies) == 0 {
		return []domain.PolicySummary{}, nil
	}

	// 1. 提取所有涉及的 Action 以便批量拉取元数据
	var allActions []string
	for _, p := range policies {
		allActions = append(allActions, p.CollectActions()...)
	}

	// 2. 并行获取三组核心底座数据 (仅执行一次)
	perms, serviceTotal, svcMetas, err := s.fetchPolicySummaryData(ctx, allActions)
	if err != nil {
		return nil, err
	}

	// 3. 预构建索引字典 (Code -> Name)
	svcNameMap := lo.SliceToMap(svcMetas, func(s domain.Service) (string, string) {
		return s.Code, s.Name
	})
	permMap := lo.SliceToMap(perms, func(p domain.Permission) (string, domain.Permission) { return p.Code, p })

	// 4. 迭代组装每个 Policy 的摘要结果
	results := make([]domain.PolicySummary, 0, len(policies))
	for _, p := range policies {
		results = append(results, s.assemblePolicySummary(p, permMap, serviceTotal, svcNameMap))
	}

	return results, nil
}

// assemblePolicySummary 内存级组装单个策略摘要
func (s *permissionService) assemblePolicySummary(
	p domain.Policy,
	permMap map[string]domain.Permission, // permMap 包含本次批次涉及的所有权限
	serviceTotal map[string]int64,
	svcNameMap map[string]string) domain.PolicySummary {

	// 1. 获取所有命中的权限点及其对应的效果
	type analyzedPerm struct {
		perm   domain.Permission
		effect domain.Effect
	}
	var analyzed []analyzedPerm
	for _, perm := range permMap {
		if stmt, ok := p.FindApplicableStatement(perm.Code); ok {
			analyzed = append(analyzed, analyzedPerm{perm: perm, effect: stmt.Effect})
		}
	}

	// 2. 按 (服务ID + 效果) 进行二级聚合
	// 这样同一个服务（如 IAM）的 ALLOW 和 DENY 会被拆分成两组
	groups := lo.GroupBy(analyzed, func(ap analyzedPerm) string {
		return fmt.Sprintf("%s:%s", ap.perm.Service, ap.effect)
	})

	// 3. 构建服务摘要列表
	summaries := lo.MapToSlice(groups, func(_ string, aps []analyzedPerm) domain.PolicyServiceSummary {
		svcCode := aps[0].perm.Service
		effect := aps[0].effect

		scope := p.ResolveResourceScope(svcCode)
		total := serviceTotal[svcCode]
		count := int64(len(aps))

		level := domain.AccessLevelPartial
		// 只有在 ALLOW 且 覆盖全量资源时才标记为 ALL 访问
		if effect == domain.Allow && count >= total && scope == "*" {
			level = domain.AccessLevelAll
		}

		svcName := svcCode
		if name, ok := svcNameMap[svcCode]; ok {
			svcName = name
		}

		return domain.PolicyServiceSummary{
			ServiceCode:   svcCode,
			ServiceName:   svcName,
			Effect:        effect,
			Level:         level,
			GrantedCount:  int(count),
			TotalCount:    int(total),
			ResourceScope: scope,
			Actions: lo.Map(aps, func(ap analyzedPerm, _ int) domain.GrantedAction {
				stmt, _ := p.FindApplicableStatement(ap.perm.Code)
				return domain.GrantedAction{
					Code:      ap.perm.Code,
					Name:      ap.perm.Name,
					Group:     ap.perm.Group,
					Effect:    ap.effect,
					Resource:  stmt.Resource,
					Condition: stmt.Condition,
				}
			}),
		}
	})

	return domain.PolicySummary{Policy: p, Services: summaries}
}

// fetchPolicySummaryData 并行获取策略摘要分析所需的三组基础数据
func (s *permissionService) fetchPolicySummaryData(ctx context.Context, actions []string) (
	[]domain.Permission, map[string]int64, []domain.Service, error,
) {
	var (
		eg           errgroup.Group
		perms        []domain.Permission
		serviceTotal map[string]int64
		svcMetas     []domain.Service
	)

	eg.Go(func() error {
		var err error
		// 优化：如果包含通配符 "*"，则拉取全量权限点以进行完整分析
		if lo.Contains(actions, "*") {
			perms, err = s.permRepo.ListAllPermissions(ctx)
		} else {
			perms, err = s.permRepo.FindByActions(ctx, lo.Uniq(actions))
		}
		return err
	})

	eg.Go(func() error {
		var err error
		serviceTotal, err = s.permRepo.CountByService(ctx)
		return err
	})

	eg.Go(func() error {
		var err error
		svcMetas, err = s.resourceSvc.ListServices(ctx)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, nil, nil, err
	}

	return perms, serviceTotal, svcMetas, nil
}

package permission

import (
	"context"
	"strings"
	"sync"

	"github.com/Duke1616/eiam/internal/pkg/searcher"
	"github.com/Duke1616/eiam/internal/repository/dao"
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

type permissionService struct {
	enforcer    *casbin.SyncedEnforcer
	resourceSvc resource.IResourceService
	roleSvc     role.IRoleService
	permRepo    repository.IPermissionRepository
	policySvc   policy.IPolicyService
	authorizer  authz.IAuthorizer

	// registry 注册中心 (组合模式处理：全域搜索与计数聚合)
	registry searcher.ISubjectRegistry
}

func NewPermissionService(
	en *casbin.SyncedEnforcer,
	policySvc policy.IPolicyService,
	roleSvc role.IRoleService,
	registry searcher.ISubjectRegistry,
	resourceSvc resource.IResourceService,
	permRepo repository.IPermissionRepository,
	auth authz.IAuthorizer) IPermissionService {
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

	// 3.策略预加载 (优化点：减少重复查询)
	policies, err := s.getEffectivePolicies(ctx, username)
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

	policies, err := s.getEffectivePolicies(ctx, username)
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
func (s *permissionService) getEffectivePolicies(ctx context.Context, username string) ([]domain.Policy, error) {
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

func (s *permissionService) AssignRoleToUser(ctx context.Context, username string, roleCode string) (bool, error) {
	// 前置校验角色是否存在且合法
	if _, err := s.roleSvc.GetByCode(ctx, roleCode); err != nil {
		return false, err
	}

	tid := ctxutil.GetTenantID(ctx).String()
	return s.enforcer.AddGroupingPolicy(
		domain.UserSubject(username),
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

// GetRolesForUser 获取用户当前拥有的所有角色清单 (含继承关系)
func (s *permissionService) GetRolesForUser(ctx context.Context, username string) ([]string, error) {
	tid := ctxutil.GetTenantID(ctx).String()

	roles, err := s.enforcer.GetImplicitRolesForUser(domain.UserSubject(username), tid)
	if err != nil {
		return nil, err
	}

	return lo.Uniq(roles), nil
}

func (s *permissionService) AssignPolicyToUser(ctx context.Context, username string, policyCode string) (bool, error) {
	err := s.policySvc.AttachPolicyToUser(ctx, username, policyCode)
	return err == nil, err
}

func (s *permissionService) AssignPolicyToRole(ctx context.Context, roleCode, policyCode string) (bool, error) {
	err := s.policySvc.AttachPolicyToRole(ctx, roleCode, policyCode)
	return err == nil, err
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

	// 获取策略分配
	assignments, total, err := s.policySvc.ListAssignments(ctx, query.Offset, query.Limit, subType, query.Keyword)
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
	// 1. 并行获取三组基础数据
	perms, serviceTotal, svcMetas, err := s.fetchPolicySummaryData(ctx, p.CollectActions())
	if err != nil {
		return domain.PolicySummary{}, err
	}

	// 2. 构建索引
	svcNameMap := slice.ToMap(svcMetas, func(s domain.Service) string { return s.Code })
	svcGroups := lo.GroupBy(perms, func(p domain.Permission) string { return p.Service })

	// 3. 声明式组装：Map → 服务级摘要切片
	summaries := lo.MapToSlice(svcGroups, func(svcCode string, hitPerms []domain.Permission) domain.PolicyServiceSummary {
		scope := p.ResolveResourceScope(svcCode)
		total := serviceTotal[svcCode]
		hitCount := int64(len(hitPerms))

		level := domain.AccessLevelPartial
		if hitCount >= total && scope == "*" {
			level = domain.AccessLevelAll
		}

		svcName := svcCode
		if meta, ok := svcNameMap[svcCode]; ok {
			svcName = meta.Name
		}

		return domain.PolicyServiceSummary{
			ServiceCode:   svcCode,
			ServiceName:   svcName,
			Level:         level,
			GrantedCount:  int(hitCount),
			TotalCount:    int(total),
			ResourceScope: scope,
			// 反向映射：将权限点追溯到其 Statement 的边界条件
			Actions: lo.FilterMap(hitPerms, func(perm domain.Permission, _ int) (domain.GrantedAction, bool) {
				stmt, ok := p.FindGrantingStatement(perm.Code)
				if !ok {
					return domain.GrantedAction{}, false
				}
				return domain.GrantedAction{
					Code:      perm.Code,
					Name:      perm.Name,
					Group:     perm.Group,
					Resource:  stmt.Resource,
					Condition: stmt.Condition,
				}, true
			}),
		}
	})

	return domain.PolicySummary{Policy: p, Services: summaries}, nil
}

// fetchPolicySummaryData 并行获取策略摘要分析所需的三组基础数据
func (s *permissionService) fetchPolicySummaryData(ctx context.Context, actions []string) (
	[]domain.Permission, map[string]int64, []domain.Service, error,
) {
	var (
		perms        []domain.Permission
		serviceTotal map[string]int64
		svcMetas     []domain.Service
		eg           errgroup.Group
	)

	eg.Go(func() error {
		var err error
		perms, err = s.permRepo.FindByActions(ctx, lo.Uniq(actions))
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

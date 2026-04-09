package resource

import (
	"context"
	_ "embed"

	"strings"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/pkg/utils"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ekit/slice"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
	"gopkg.in/yaml.v3"
)

//go:embed init/memu.yaml
var menuYaml []byte

// IInitializer 负责中心化权限决策中心（EIAM）的资产同步接口。
// 支持“本地自发现”与“远端 SDK 协议上报”两种归一化的对等发现逻辑。
type IInitializer interface {
	// SyncDiscoveryAPIs 为 EIAM 本地服务提供基于 SDK Collector 的自发现支持 (SDK 模式)
	SyncDiscoveryAPIs(ctx context.Context, providers []capability.PermissionProvider, router *gin.Engine) error

	// SyncSDKDiscovery 处理符合标准 SDK 协议定义的资产同步请求 (SDK 模式)
	SyncSDKDiscovery(ctx context.Context, req capability.SyncRequest) error

	// SyncMenus 根据本地 YAML 定义，增量对齐 EIAM 自身维护的菜单物理资产
	SyncMenus(ctx context.Context) error
}

// Initializer 资产同步引擎实现。
type Initializer struct {
	repo     repository.IResourceRepository
	permRepo repository.IPermissionRepository
	service  string // 当前服务的唯一标识，用于 URN 生成的前缀上下文

	sorter *utils.Sorter[*domain.Menu, *domain.Menu]
}

func NewResourceInitializer(repo repository.IResourceRepository, permRepo repository.IPermissionRepository, service string) IInitializer {
	return &Initializer{
		repo:     repo,
		permRepo: permRepo,
		service:  iif(service != "", service, "eiam"),
		sorter: utils.NewSorter(func(m *domain.Menu, idx int) *domain.Menu {
			m.Sort = int64((idx + 1) * utils.DefaultIndexGap)
			return m
		}),
	}
}

// SyncDiscoveryAPIs 提供 EIAM 本地全量资产的“一键同步”封装。
func (i *Initializer) SyncDiscoveryAPIs(ctx context.Context, providers []capability.PermissionProvider, router *gin.Engine) error {
	// 1. 资产收集：利用 SDK 扫描本地注册的 Provider 与路由装饰器
	collector := capability.NewCollector(router).RegisterProviders(providers...)
	perms, apis := collector.Collect()

	// 2. 协议分发：转化为标准 SDK 协议语义执行同步内核逻辑
	return i.SyncSDKDiscovery(ctx, capability.SyncRequest{
		Service:     i.service,
		Permissions: perms,
		APIs:        apis,
	})
}

// SyncSDKDiscovery 实现高性能同步内核逻辑 (SDK 模式)。
// 流程：底座对齐 -> 资产分析 -> 批量落盘。
func (i *Initializer) SyncSDKDiscovery(ctx context.Context, req capability.SyncRequest) error {
	// 1. 底座对齐：预加载全量逻辑权限，并补全上报中缺失的底数 (含物理资产引用的未知 Code)
	permMap, err := i.alignPermissionBaseline(ctx, req)
	if err != nil {
		return err
	}

	// 2. 资产识别：在内存中完成物理资产判重，并聚合染色关系
	toCreate, bindings, err := i.analyzeDiscoveryAssets(ctx, req)
	if err != nil {
		return err
	}

	// 3. 高能同步：执行高性能批量落地与染色
	return i.persistenceDiscovery(ctx, toCreate, bindings, permMap)
}

// alignPermissionBaseline 确保权限底座包含所有已知的和被引用的权限码，并返回最新索引 Map
func (i *Initializer) alignPermissionBaseline(ctx context.Context, req capability.SyncRequest) (map[string]domain.Permission, error) {
	// 1. 提取全量候选 Code (显式声明的 + 物理资产引用的)
	allCandidatePerms := i.extractAllCandidatePerms(req)

	// 3. 批量补全缺失权限 (全量 Upsert，保证元数据对齐)
	err := i.syncPermissionsBatch(ctx, req.Service, allCandidatePerms)
	if err != nil {
		return nil, err
	}

	// 4. 再次刷新索引，确保能获取到新录入权限的自增 ID
	return i.getPermissionIndex(ctx)
}

// extractAllCandidatePerms 提取所有需要保证存在的权限定义
// 策略：当物理资产引用了某个 Code，但该 Code 不在显式声明列表中时，为其创建 Skeleton 占位符
func (i *Initializer) extractAllCandidatePerms(req capability.SyncRequest) []capability.Permission {
	codeMap := make(map[string]capability.Permission)

	// 1. 扫描物理 API 里的所有主 Code，先初始化为 Skeleton (骨架)
	for _, api := range req.APIs {
		code := api.Code
		if code == "" {
			continue
		}

		if _, ok := codeMap[code]; !ok {
			group := "Auto-discovered"
			if api.Group != "" {
				group = api.Group
			}
			codeMap[code] = capability.Permission{
				Code:  code,
				Name:  api.Name,
				Group: group,
			}
		}
	}

	// 2. 收集显式声明的逻辑权限，高优先级覆盖 Skeleton 里的元数据 (Name/Desc/Group)
	for _, p := range req.Permissions {
		codeMap[p.Code] = p
	}

	// 3. 转化为切片输出
	res := make([]capability.Permission, 0, len(codeMap))
	for _, p := range codeMap {
		res = append(res, p)
	}
	return res
}

// analyzeDiscoveryAssets 分析增量 API 资产并聚合逻辑染色映射关系
func (i *Initializer) analyzeDiscoveryAssets(ctx context.Context, req capability.SyncRequest) ([]domain.API, map[string][]string, error) {
	apiIndex, err := i.getAPIIndex(ctx, req.Service)
	if err != nil {
		return nil, nil, err
	}

	toCreate := make([]domain.API, 0)
	bindings := make(map[string][]string)

	for _, a := range req.APIs {
		service := req.Service
		if a.Service != "" {
			service = a.Service
		}
		api := domain.API{
			Service: service,
			Method:  a.Method,
			Path:    a.Path,
			Name:    a.Name,
		}

		// 判重：仅录入不存在的资产
		if _, ok := apiIndex[api.URN()]; !ok {
			toCreate = append(toCreate, api)
		}

		// 聚合：主权限码绑定到当前 API 的 URN
		// 依赖权限码 (Includes) 不参与当前 API 的 URN 绑定，仅用于 Skeleton 发现
		if a.Code != "" {
			bindings[a.Code] = append(bindings[a.Code], api.URN())
		}
	}

	return toCreate, bindings, nil
}

// persistenceDiscovery 执行资产落地与最终染色关系对齐
func (i *Initializer) persistenceDiscovery(ctx context.Context, toCreate []domain.API, bindings map[string][]string, permMap map[string]domain.Permission) error {
	// 1. API 资产批量落盘
	if len(toCreate) > 0 {
		if err := i.repo.BatchCreateAPI(ctx, toCreate); err != nil {
			elog.DefaultLogger.Error("API 资产同步落地失败", elog.FieldErr(err))
		}
	}

	// 2. 逻辑权限批量染色 (Global Binding)
	if len(bindings) > 0 {
		if err := i.permRepo.BatchBindResources(ctx, 0, bindings); err != nil {
			elog.DefaultLogger.Error("API 资产逻辑染色失败", elog.FieldErr(err))
		}
	}

	return nil
}

// getPermissionIndex 构建权限码 -> 权限对象的全量索引
func (i *Initializer) getPermissionIndex(ctx context.Context) (map[string]domain.Permission, error) {
	all, err := i.permRepo.ListAllPermissions(ctx)
	if err != nil {
		return nil, err
	}

	return slice.ToMap(all, func(element domain.Permission) string {
		return element.Code
	}), nil
}

// getAPIIndex 构建物理标识 URN -> 接口对象的索引
func (i *Initializer) getAPIIndex(ctx context.Context, service string) (map[string]struct{}, error) {
	apis, err := i.repo.ListAPIsByService(ctx, service)
	if err != nil {
		return nil, err
	}

	return slice.ToMapV(apis, func(a domain.API) (string, struct{}) {
		return a.URN(), struct{}{}
	}), nil
}

// syncPermissionsBatch 批量同步权限底数
func (i *Initializer) syncPermissionsBatch(ctx context.Context, defaultService string, perms []capability.Permission) error {
	// 1. 转化为领域对象清单 (全量同步，依赖 DAO 层的 Upsert 逻辑保证一致性)
	toCreate := slice.Map(perms, func(_ int, p capability.Permission) domain.Permission {
		service := defaultService
		if parts := strings.Split(p.Code, ":"); len(parts) > 0 && parts[0] != "" {
			service = parts[0]
		}

		return domain.Permission{
			Service: service,
			Code:    p.Code,
			Name:    p.Name,
			Group:   p.Group,
			Needs:   p.Needs,
		}
	})

	// 2. 批量落盘 (Upsert)
	if len(toCreate) > 0 {
		return i.permRepo.BatchCreatePermission(ctx, toCreate)
	}
	return nil
}

func (i *Initializer) SyncMenus(ctx context.Context) error {
	// 1. 系统预热：加载内置菜单元数据并重平衡权重
	menus, err := i.loadBuiltinMenus()
	if err != nil {
		return err
	}
	i.rebalanceMenuTree(menus)

	// 2. 物理落地：执行菜单资产的高速原子化同步
	if err = i.repo.SyncMenuTree(ctx, menus); err != nil {
		return err
	}

	// 3. 染色对齐：一次性执行菜单与权限码的全局绑定
	return i.syncMenuBindings(ctx, menus)
}

// loadBuiltinMenus 封装 YAML 加载与内置资源的内存反序列化逻辑
func (i *Initializer) loadBuiltinMenus() ([]*domain.Menu, error) {
	var menus []*domain.Menu
	if err := yaml.Unmarshal(menuYaml, &menus); err != nil {
		return nil, err
	}
	return menus, nil
}

// syncMenuBindings 封装菜单资源与逻辑权限的染色挂载全流程
func (i *Initializer) syncMenuBindings(ctx context.Context, menus []*domain.Menu) error {
	bindings := make(map[string][]string)
	i.collectMenuBindings(menus, bindings)

	if len(bindings) == 0 {
		return nil
	}

	return i.permRepo.BatchBindResources(ctx, 0, bindings)
}

func iif(cond bool, t, f string) string {
	if cond {
		return t
	}
	return f
}

// collectMenuBindings 利用通用层级走访器，提取整棵树中所有声明了权限码的资源 URN
func (i *Initializer) collectMenuBindings(menus []*domain.Menu, bindings map[string][]string) {
	utils.WalkHierarchical(menus, func(m *domain.Menu) []*domain.Menu {
		return m.Children
	}, func(m *domain.Menu) {
		if m.PermissionCode != "" {
			bindings[m.PermissionCode] = append(bindings[m.PermissionCode], m.URN())
		}
	})
}

func (i *Initializer) rebalanceMenuTree(menus []*domain.Menu) {
	// 极致优雅：通过通用排序引擎一键递归重置整颗树的权重，消除局部循环逻辑与分配压力
	i.sorter.RebalanceHierarchical(menus, func(m *domain.Menu) []*domain.Menu {
		return m.Children
	})
}

package resource

import (
	"context"
	_ "embed"
	"fmt"

	"strings"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/pkg/utils"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ekit/slice"
	"github.com/gin-gonic/gin"
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
	// 1. 确保权限底数存在
	if err := i.syncPermissionsBatch(ctx, req.Service, req.Permissions); err != nil {
		return err
	}

	// 2. 聚合所有上报资产，并聚合染色关系
	allAPIs, bindings, err := i.analyzeDiscoveryAssets(ctx, req)
	if err != nil {
		return err
	}

	// 3. 执行高性能批量落地与染色
	return i.persistenceDiscovery(ctx, req.Service, allAPIs, bindings)
}

// analyzeDiscoveryAssets 分析增量 API 资产并聚合逻辑染色映射关系
func (i *Initializer) analyzeDiscoveryAssets(ctx context.Context, req capability.SyncRequest) ([]domain.API, map[string][]string, error) {
	allAPIs := make([]domain.API, 0, len(req.APIs))
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

		allAPIs = append(allAPIs, api)

		// 聚合：主权限码绑定到当前 API 的 URN
		if a.Code != "" {
			bindings[a.Code] = append(bindings[a.Code], api.URN())
		}
	}

	return allAPIs, bindings, nil
}

// persistenceDiscovery 执行资产落地与最终染色关系对齐
func (i *Initializer) persistenceDiscovery(ctx context.Context, service string, toSync []domain.API, bindings map[string][]string) error {
	// 1. API 资产批量对齐 (Full-Sync)
	if len(toSync) > 0 {
		if err := i.repo.SyncAPIs(ctx, service, toSync); err != nil {
			return fmt.Errorf("API 资产同步落地失败: %w", err)
		}
	}

	// 2. 逻辑权限批量染色 (Global Binding)
	if len(bindings) > 0 {
		if err := i.permRepo.BatchBindResources(ctx, bindings); err != nil {
			return fmt.Errorf("API 资产逻辑染色失败: %w", err)
		}
	}

	return nil
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
	// 1. 加载内置菜单元数据
	menus, err := i.loadBuiltinMenus()
	if err != nil {
		return err
	}

	// 2. 打平结构、血缘自映射
	i.sorter.RebalanceHierarchical(menus, func(m *domain.Menu) []*domain.Menu {
		return m.Children
	})

	flatList := menus.Flatten()

	// 提取映射
	bindings := make(map[string][]string)
	for _, m := range flatList {
		if m.PermissionCode != "" {
			bindings[m.PermissionCode] = append(bindings[m.PermissionCode], m.URN())
		}
	}

	// 3.执行菜单资产的高速原子化同步
	if err = i.repo.SyncMenus(ctx, flatList); err != nil {
		return err
	}

	// 4. 一次性执行菜单与权限码的全局绑定 (Full-Sync 版)
	allURNs := slice.Map(flatList, func(_ int, m domain.Menu) string { return m.URN() })
	return i.permRepo.SyncResourceBindings(ctx, allURNs, bindings)
}

// loadBuiltinMenus 封装 YAML 加载与内置资源的内存反序列化逻辑
func (i *Initializer) loadBuiltinMenus() (domain.MenuTree, error) {
	var menus []*domain.Menu
	if err := yaml.Unmarshal(menuYaml, &menus); err != nil {
		return nil, err
	}
	return menus, nil
}

func iif(cond bool, t, f string) string {
	if cond {
		return t
	}
	return f
}

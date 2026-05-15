package resource

import (
	"context"
	_ "embed"

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

//go:embed init/service.yaml
var serviceYaml []byte

// IInitializer 负责中心化权限决策中心（EIAM）的资产同步接口。
// 支持“本地自发现”与“远端 SDK 协议上报”两种归一化的对等发现逻辑。
type IInitializer interface {
	// SyncDiscoveryAPIs 为 EIAM 本地服务提供基于 SDK Collector 的自发现支持 (SDK 模式)
	SyncDiscoveryAPIs(ctx context.Context, providers []capability.PermissionProvider, router *gin.Engine) error

	// SyncSDKDiscovery 处理符合标准 SDK 协议定义的资产同步请求 (SDK 模式)
	SyncSDKDiscovery(ctx context.Context, req capability.SyncRequest) error

	// SyncMenus 根据本地 YAML 定义，增量对齐 EIAM 自身维护的菜单物理资产
	SyncMenus(ctx context.Context) error

	// SyncServices 根据本地 YAML 定义，全量对齐服务目录
	SyncServices(ctx context.Context) error

	// NewPipeline 创建一个同步任务流 (Pipeline 模式)
	NewPipeline(ctx context.Context) *SyncPipeline
}

// Initializer 资产同步引擎实现。
type Initializer struct {
	repo        repository.IResourceRepository
	permRepo    repository.IPermissionRepository
	resourceSvc IResourceService
	reconciler  Reconciler
	registry    capability.Registry
	service     string // 当前服务的唯一标识，用于 URN 生成的前缀上下文
	logger      *elog.Component

	sorter *utils.Sorter[*domain.Menu, *domain.Menu]
}

func NewResourceInitializer(repo repository.IResourceRepository, permRepo repository.IPermissionRepository, resourceSvc IResourceService, reconciler Reconciler, registry capability.Registry, service string) IInitializer {
	if service == "" {
		service = "eiam"
	}

	return &Initializer{
		repo:        repo,
		permRepo:    permRepo,
		resourceSvc: resourceSvc,
		reconciler:  reconciler,
		registry:    registry,
		service:     service,
		logger:      elog.DefaultLogger.With(elog.FieldComponent("resource-initializer")),
		sorter: utils.NewSorter(func(m *domain.Menu, idx int) *domain.Menu {
			m.Sort = int64((idx + 1) * utils.DefaultIndexGap)
			return m
		}),
	}
}

// SyncDiscoveryAPIs 为 EIAM 本地服务提供基于 SDK Collector 的自发现支持 (SDK 模式)
func (i *Initializer) SyncDiscoveryAPIs(ctx context.Context, providers []capability.PermissionProvider, router *gin.Engine) error {
	return capability.NewSyncer(i.service, i.registry,
		capability.WithPermissions(providers...),
		capability.WithRouter(router),
	).Sync(ctx)
}

// SyncSDKDiscovery 实现高性能同步内核逻辑 (SDK 模式)。
// 流程：底座对齐 -> 资产分析 -> 批量落盘。
// SyncSDKDiscovery 实现高性能同步内核逻辑 (SDK 模式)。
func (i *Initializer) SyncSDKDiscovery(ctx context.Context, req capability.SyncRequest) error {
	// 统一交付给对账引擎执行全量对账 (包含逻辑权限、物理 API、菜单资产及资源染色)
	return i.reconciler.Reconcile(ctx, req)
}

func (i *Initializer) SyncServices(ctx context.Context) error {
	// 1. 加载内置服务目录元数据 (泛型加载)
	services, err := loadYAML[[]domain.Service](serviceYaml)
	if err != nil {
		return err
	}

	// 2. 执行批量对齐
	return i.resourceSvc.BatchRegisterServices(ctx, services)
}

func (i *Initializer) SyncMenus(ctx context.Context) error {
	// 1. 加载内置菜单元数据 (泛型加载)
	menus, err := loadYAML[domain.MenuTree](menuYaml)
	if err != nil {
		return err
	}

	// 2. 打平结构、血缘自映射
	i.sorter.RebalanceHierarchical(menus, func(m *domain.Menu) []*domain.Menu {
		return m.Children
	})

	flatList := menus.Flatten(i.service)

	// 提取映射
	bindings := make(map[string][]string)
	for _, m := range flatList {
		if m.PermissionCode != "" {
			bindings[m.PermissionCode] = append(bindings[m.PermissionCode], m.URN())
		}
	}

	// 3.执行菜单资产的高速原子化同步
	if err = i.repo.SyncMenus(ctx, i.service, flatList); err != nil {
		return err
	}

	// 4. 一次性执行菜单与权限码的全局绑定 (Full-Sync 版)
	allURNs := slice.Map(flatList, func(_ int, m domain.Menu) string { return m.URN() })
	return i.permRepo.SyncResourceBindings(ctx, allURNs, bindings)
}


// loadYAML 泛型 YAML 反序列化工具函数
func loadYAML[T any](data []byte) (T, error) {
	var res T
	if err := yaml.Unmarshal(data, &res); err != nil {
		return res, err
	}
	return res, nil
}

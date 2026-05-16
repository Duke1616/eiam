package resource

import (
	"context"
	_ "embed"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/service/resource/ingestion"
	"github.com/Duke1616/eiam/pkg/utils"
	"github.com/Duke1616/eiam/pkg/web/capability"
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
	engine   ingestion.Engine
	registry capability.Registry
	logger   *elog.Component

	sorter *utils.Sorter[*domain.Menu, *domain.Menu]
}

func NewResourceInitializer(engine ingestion.Engine, registry capability.Registry) IInitializer {
	return &Initializer{
		engine:   engine,
		registry: registry,
		logger:   elog.DefaultLogger.With(elog.FieldComponent("resource-initializer")),
		sorter: utils.NewSorter(func(m *domain.Menu, idx int) *domain.Menu {
			m.Sort = int64((idx + 1) * utils.DefaultIndexGap)
			return m
		}),
	}
}

// SyncDiscoveryAPIs 为 EIAM 本地服务提供基于 SDK Collector 的自发现支持 (SDK 模式)
func (i *Initializer) SyncDiscoveryAPIs(ctx context.Context, providers []capability.PermissionProvider, router *gin.Engine) error {
	return capability.NewSyncer(i.registry,
		capability.WithPermissions(providers...),
		capability.WithRouter(router),
	).Sync(ctx)
}

// SyncSDKDiscovery 处理符合标准 SDK 协议定义的资产同步请求 (SDK 模式)。
func (i *Initializer) SyncSDKDiscovery(ctx context.Context, req capability.SyncRequest) error {
	return i.engine.Ingest(ctx, ingestion.FromSyncRequest(req))
}

func (i *Initializer) SyncServices(ctx context.Context) error {
	// 1. 加载内置服务目录元数据 (泛型加载)
	services, err := loadYAML[[]domain.Service](serviceYaml)
	if err != nil {
		return err
	}

	// 2. 执行批量对齐
	return i.engine.IngestServices(ctx, services)
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

	// 3. 委托给统一录入引擎执行落盘与绑定
	return i.engine.IngestMenus(ctx, menus)
}

// loadYAML 泛型 YAML 反序列化工具函数
func loadYAML[T any](data []byte) (T, error) {
	var res T
	if err := yaml.Unmarshal(data, &res); err != nil {
		return res, err
	}
	return res, nil
}

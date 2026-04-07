package resource

import (
	"context"
	_ "embed"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/pkg/utils"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
	"gopkg.in/yaml.v3"
)

//go:embed init/memu.yaml
var menuYaml []byte

// IInitializer 负责系统资产的同步接口定义
type IInitializer interface {
	// SyncDiscoveryAPIs 自动化发现并同步逻辑权限与物理 API 资产
	SyncDiscoveryAPIs(ctx context.Context, providers []capability.PermissionProvider, router *gin.Engine) error

	// SyncMenus 同步菜单物理资产
	SyncMenus(ctx context.Context) error
}

// Initializer 负责中心化 EIAM 的资产同步逻辑。
type Initializer struct {
	repo     repository.IResourceRepository
	permRepo repository.IPermissionRepository
	service  string // 默认服务标识，用于 URN 生成

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

// SyncPermissions 使用 SDK 暴露的 Permission 结构同步权限底数 (逻辑能力项)
func (i *Initializer) SyncPermissions(ctx context.Context, perms []capability.Permission) error {
	elog.DefaultLogger.Info("开始启动逻辑权限（能力项）全量同步任务...", elog.Int("permissions_count", len(perms)))

	for _, p := range perms {
		dp := domain.Permission{
			Code:  p.Code,
			Name:  p.Name,
			Desc:  p.Desc,
			Group: p.Group,
		}
		if _, err := i.permRepo.CreatePermission(ctx, dp); err != nil {
			elog.DefaultLogger.Debug("逻辑权限底数已存在或跳过同步", elog.String("code", p.Code))
		}
	}

	elog.DefaultLogger.Info("逻辑权限底数同步完成")
	return nil
}

// SyncSDKDiscovery 处理来自 SDK 的完整资产上报逻辑
func (i *Initializer) SyncSDKDiscovery(ctx context.Context, service string, perms []capability.Permission, apis []capability.ResourceInfo) error {
	// 1. 同步逻辑权限
	if err := i.SyncPermissions(ctx, perms); err != nil {
		return err
	}

	// 2. 同步物理路由资产与自动权限绑定
	for _, info := range apis {
		svc := iif(info.Service != "", info.Service, service)

		api := domain.API{
			Service: svc,
			Method:  info.Method,
			Path:    info.Path,
			Name:    info.Name,
		}

		// 录入物理资产
		if _, err := i.repo.CreateAPI(ctx, api); err != nil {
			elog.DefaultLogger.Debug("API 资产同步跳过：可能已存在", elog.String("path", api.Path))
		}

		// 执行自动权限绑定 (Dev-to-Bind)
		for _, code := range info.Codes {
			p, err := i.permRepo.GetByCode(ctx, code)
			if err != nil {
				elog.DefaultLogger.Warn("绑定跳过：未找到逻辑权限码", elog.String("code", code), elog.String("path", api.Path))
				continue
			}

			if err := i.permRepo.BindResources(ctx, p.ID, code, []string{api.URN()}); err != nil {
				elog.DefaultLogger.Error("API 权限自动绑定失败", elog.String("code", code), elog.String("path", api.Path))
			}
		}
	}

	return nil
}

// SyncDiscoveryAPIs 为本地 EIAM 提供基于 SDK Collector 的自发现支持
func (i *Initializer) SyncDiscoveryAPIs(ctx context.Context, providers []capability.PermissionProvider, router *gin.Engine) error {
	collector := capability.NewCollector(router).RegisterProviders(providers...)
	perms, apis := collector.Collect()

	return i.SyncSDKDiscovery(ctx, i.service, perms, apis)
}

func (i *Initializer) SyncMenus(ctx context.Context) error {
	var menus []*domain.Menu
	if err := yaml.Unmarshal(menuYaml, &menus); err != nil {
		return err
	}

	i.applyCalculatedSort(menus)
	if err := i.repo.SyncMenuTree(ctx, menus); err != nil {
		return err
	}

	bindings := make(map[string][]string)
	i.collectMenuBindings(menus, bindings)

	for code, urns := range bindings {
		p, err := i.permRepo.GetByCode(ctx, code)
		if err == nil {
			_ = i.permRepo.BindResources(ctx, p.ID, code, urns)
		}
	}

	return nil
}

func iif(cond bool, t, f string) string {
	if cond {
		return t
	}
	return f
}

func (i *Initializer) collectMenuBindings(menus []*domain.Menu, bindings map[string][]string) {
	for _, m := range menus {
		if m.PermissionCode != "" {
			bindings[m.PermissionCode] = append(bindings[m.PermissionCode], m.URN())
		}
		i.collectMenuBindings(m.Children, bindings)
	}
}

func (i *Initializer) applyCalculatedSort(menus []*domain.Menu) {
	// 极致优雅：通过通用排序引擎一键递归重置整颗树的权重，消除局部循环逻辑与分配压力
	i.sorter.RebalanceHierarchical(menus, func(m *domain.Menu) []*domain.Menu {
		return m.Children
	})
}

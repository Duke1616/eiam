package ingestion

import (
	"context"
	"fmt"
	"strings"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/gotomicro/ego/core/elog"
	"github.com/samber/lo"
)

// Engine 统一资源录入引擎，负责将各类来源的资产归一化后落盘并维护绑定关系。
type Engine interface {
	// Ingest 执行全量资产同步（SDK 上报/远端发现）。
	// 依次完成 Permission → API → Menu 的同步，最后批量增量绑定资源。
	Ingest(ctx context.Context, snap Snapshot) error

	// IngestMenus 执行本地菜单资产的全量同步（Full-Sync 模式）。
	// 同步菜单元数据的同时，对绑定关系执行先删后插的强一致性对齐。
	IngestMenus(ctx context.Context, menus domain.MenuTree) error

	// IngestServices 执行服务目录的批量注册或更新。
	IngestServices(ctx context.Context, services []domain.Service) error
}

type engine struct {
	permRepo repository.IPermissionRepository
	resRepo  repository.IResourceRepository
	svcRepo  repository.IServiceRepository
	logger   *elog.Component
}

// NewEngine 构建统一资源录入引擎。
func NewEngine(
	permRepo repository.IPermissionRepository,
	resRepo repository.IResourceRepository,
	svcRepo repository.IServiceRepository,
) Engine {
	return &engine{
		permRepo: permRepo,
		resRepo:  resRepo,
		svcRepo:  svcRepo,
		logger:   elog.DefaultLogger.With(elog.FieldComponent("resource-ingestion")),
	}
}

// Ingest 执行全量资产同步（增量绑定模式）。
// 流程：权限对齐 → API 对齐 → 菜单元数据对齐 → API 资源绑定染色。
//
// NOTE: menu 类型的绑定关系由 IngestMenus 统一全量管理，Ingest 只负责绑定
// API 类型的物理资源，两者职责严格隔离，避免并发时相互覆盖导致菜单绑定丢失。
func (e *engine) Ingest(ctx context.Context, snap Snapshot) error {
	if err := snap.Validate(); err != nil {
		return fmt.Errorf("资产快照校验失败: %w", err)
	}
	return e.permRepo.Transaction(ctx, func(txCtx context.Context) error {
		// 1. 物理清空该服务的所有旧逻辑权限和资源映射关系
		if err := e.permRepo.PhysicalClearService(txCtx, snap.Service, snap.Source); err != nil {
			return fmt.Errorf("清空旧权限与映射失败: %w", err)
		}

		// 2. 物理清空该服务的所有 API 物理资产
		if err := e.resRepo.DeleteAPIsByServiceAndURNs(txCtx, snap.Service, snap.Source, nil); err != nil {
			return fmt.Errorf("清空旧 API 资产失败: %w", err)
		}

		// 3. 同步写入最新的逻辑权限点
		if err := e.permRepo.SyncPermissions(txCtx, snap.Service, snap.Source, snap.Permissions); err != nil {
			return fmt.Errorf("同步权限点失败: %w", err)
		}

		// 4. 同步写入最新的物理接口资产
		if err := e.resRepo.SyncAPIs(txCtx, snap.Service, snap.Source, snap.APIs); err != nil {
			return fmt.Errorf("同步 API 资产失败: %w", err)
		}

		// 5. 同步菜单元数据（仅写菜单表，不触碰绑定关系）
		menus := snap.Menus.Flatten()
		if len(menus) > 0 {
			if err := e.resRepo.SyncMenus(txCtx, menus); err != nil {
				return fmt.Errorf("同步菜单资产失败: %w", err)
			}
		}

		// 6. 仅绑定 API 类型的物理资源（过滤掉 menu URN，防止破坏 IngestMenus 管理的菜单绑定）
		apiBindings := filterAPIBindings(snap.Bindings)
		if len(apiBindings) > 0 {
			if err := e.permRepo.BatchBindResources(txCtx, apiBindings); err != nil {
				return fmt.Errorf("资源绑定染色失败: %w", err)
			}
		}

		e.logger.Info("资产全量同步完成",
			elog.String("service", snap.Service),
			elog.String("source", snap.Source),
			elog.Int("permissions", len(snap.Permissions)),
			elog.Int("apis", len(snap.APIs)),
			elog.Int("menus", len(menus)),
			elog.Int("api_bindings", len(apiBindings)),
		)
		return nil
	})
}

// filterAPIBindings 从绑定映射中过滤掉 menu 类型的 URN 条目。
// NOTE: menu URN 格式为 eiam:menu:{name}，menu 绑定由 IngestMenus 统一管理，
// Ingest 路径不介入，防止并发时相互覆盖导致菜单绑定丢失。
func filterAPIBindings(bindings map[string][]string) map[string][]string {
	result := make(map[string][]string, len(bindings))
	for code, urns := range bindings {
		apiURNs := lo.Filter(urns, func(urn string, _ int) bool {
			return !strings.HasPrefix(urn, "eiam:menu:")
		})
		if len(apiURNs) > 0 {
			result[code] = apiURNs
		}
	}
	return result
}

// IngestMenus 执行本地菜单资产的全量同步（Full-Sync 模式）。
// 同步菜单元数据的同时，对绑定关系执行先删后插的强一致性对齐。
func (e *engine) IngestMenus(ctx context.Context, menus domain.MenuTree) error {
	flatList := menus.Flatten()

	// 1. 提取菜单与权限码的绑定关系
	bindings := make(map[string][]string)
	for _, m := range flatList {
		if m.PermissionCode != "" {
			bindings[m.PermissionCode] = append(bindings[m.PermissionCode], m.URN())
		}
	}

	// 2. 同步菜单资产
	if err := e.resRepo.SyncMenus(ctx, flatList); err != nil {
		return fmt.Errorf("同步菜单资产失败: %w", err)
	}

	// 3. 全量对齐绑定关系（先删后插）
	allURNs := lo.Map(flatList, func(m domain.Menu, _ int) string { return m.URN() })
	if err := e.permRepo.SyncResourceBindings(ctx, allURNs, bindings); err != nil {
		return fmt.Errorf("同步菜单资源绑定失败: %w", err)
	}

	e.logger.Info("菜单资产全量同步完成",
		elog.Int("menus", len(flatList)),
		elog.Int("bindings", len(bindings)),
	)
	return nil
}

// IngestServices 执行服务目录的批量注册或更新。
func (e *engine) IngestServices(ctx context.Context, services []domain.Service) error {
	if err := e.svcRepo.BatchSave(ctx, services); err != nil {
		return fmt.Errorf("同步服务目录失败: %w", err)
	}
	e.logger.Info("服务目录同步完成", elog.Int("services", len(services)))
	return nil
}

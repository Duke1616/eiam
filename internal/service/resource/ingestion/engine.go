package ingestion

import (
	"context"
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/ecodeclub/ekit/slice"
	"github.com/gotomicro/ego/core/elog"
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
// 流程：权限对齐 → API 对齐 → 菜单对齐 → 资源绑定染色。
func (e *engine) Ingest(ctx context.Context, snap Snapshot) error {
	return e.permRepo.Transaction(ctx, func(txCtx context.Context) error {
		// 1. 物理清空该服务的所有旧逻辑权限和资源映射关系
		if err := e.permRepo.PhysicalClearService(txCtx, snap.Service); err != nil {
			return fmt.Errorf("清空旧权限与映射失败: %w", err)
		}

		// 2. 物理清空该服务的所有 API 物理资产
		if err := e.resRepo.DeleteAPIsByServiceAndURNs(txCtx, snap.Service, nil); err != nil {
			return fmt.Errorf("清空旧 API 资产失败: %w", err)
		}

		// 3. 同步写入最新的逻辑权限点
		if err := e.permRepo.SyncPermissions(txCtx, snap.Service, snap.Permissions); err != nil {
			return fmt.Errorf("同步权限点失败: %w", err)
		}

		// 4. 同步写入最新的物理接口资产
		if err := e.resRepo.SyncAPIs(txCtx, snap.Service, snap.APIs); err != nil {
			return fmt.Errorf("同步 API 资产失败: %w", err)
		}

		// 5. 同步菜单资产
		menus := snap.Menus.Flatten()
		if len(menus) > 0 {
			if err := e.resRepo.SyncMenus(txCtx, menus); err != nil {
				return fmt.Errorf("同步菜单资产失败: %w", err)
			}
		}

		// 6. 重新建立最新的资源与权限关联
		if len(snap.Bindings) > 0 {
			if err := e.permRepo.BatchBindResources(txCtx, snap.Bindings); err != nil {
				return fmt.Errorf("资源绑定染色失败: %w", err)
			}
		}

		e.logger.Info("资产全量同步完成",
			elog.String("service", snap.Service),
			elog.Int("permissions", len(snap.Permissions)),
			elog.Int("apis", len(snap.APIs)),
			elog.Int("menus", len(menus)),
			elog.Int("bindings", len(snap.Bindings)),
		)
		return nil
	})
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
	allURNs := slice.Map(flatList, func(_ int, m domain.Menu) string { return m.URN() })
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

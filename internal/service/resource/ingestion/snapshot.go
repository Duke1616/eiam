package ingestion

import (
	"fmt"
	"strings"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/samber/lo"
)

// Snapshot 定义了资源录入的内部统一资产快照。
// 所有外部来源（SDK 协议、本地 YAML）在进入处理引擎前，必须先归一化为 Snapshot。
type Snapshot struct {
	Service     string
	Source      string
	Permissions []domain.Permission
	APIs        []domain.API
	Menus       domain.MenuTree
	// Bindings 预解析的 PermissionCode -> ResourceURN 映射关系，
	// 由 Snapshot 在构建时从 APIs.Code 和 Menus.PermissionCode 中一次性提取。
	Bindings map[string][]string
}

// FromSyncRequest 将 SDK 协议的 SyncRequest 转换为内部统一的 Snapshot。
// 转换过程中一次性完成 domain 模型映射与 binding 关系解析，避免后续重复转换。
func FromSyncRequest(req capability.SyncRequest) Snapshot {
	// 1. 转换逻辑权限点
	perms := lo.Map(req.Permissions, func(p capability.Permission, _ int) domain.Permission {
		return domain.Permission{
			Service:            req.Service,
			Source:             req.Source,
			Code:               p.Code,
			Name:               p.Name,
			Group:              p.Group,
			Needs:              p.Needs,
			Scope:              p.Scope,
			Sort:               p.Sort,
			AccessScopePresets: p.AccessScopePresets,
		}
	})

	// 2. 转换物理接口并预解析 API 绑定关系
	bindings := make(map[string][]string)
	apis := lo.Map(req.APIs, func(a capability.ResourceInfo, _ int) domain.API {
		if a.Code != "" {
			urn := domain.API{Service: req.Service, Method: a.Method, Path: a.Path}.URN()
			bindings[a.Code] = append(bindings[a.Code], urn)
		}
		return domain.API{
			Service:       req.Service,
			Source:        req.Source,
			Name:          a.Name,
			Method:        a.Method,
			Path:          a.Path,
			FilterProfile: a.FilterProfile,
		}
	})

	// 3. 对 bindings 执行去重防御，防止微服务重复挂载端点导致 DB 重复插入或主键冲突
	for code, urns := range bindings {
		bindings[code] = lo.Uniq(urns)
	}

	// NOTE: 根据架构设计改造，菜单资产仅在 eiam 仓库中维护，其他微服务通过 SDK 上报的
	// SyncRequest 中的 Menus 字段全部被忽略，不做转换与 URN 绑定，从而杜绝由于外部上报菜单
	// 带来的菜单冲突及绑定关系错乱。
	return Snapshot{
		Service:     req.Service,
		Source:      req.Source,
		Permissions: perms,
		APIs:        apis,
		Menus:       nil,
		Bindings:    bindings,
	}
}

// Validate 校验业务服务上报的 AccessScope 展示模板，防止绕过 SDK Builder 直接提交无效元数据。
func (s Snapshot) Validate() error {
	for _, permission := range s.Permissions {
		seen := make(map[string]struct{}, len(permission.AccessScopePresets))
		for _, preset := range permission.AccessScopePresets {
			code := strings.TrimSpace(preset.Code)
			if code == "" || strings.TrimSpace(preset.Name) == "" || preset.Expression == nil {
				return fmt.Errorf("permission %q has incomplete AccessScope preset", permission.Code)
			}
			if _, ok := seen[code]; ok {
				return fmt.Errorf("permission %q has duplicate AccessScope preset %q", permission.Code, code)
			}
			seen[code] = struct{}{}
			if err := pbac.ValidateAccessScope(preset.Expression); err != nil {
				return fmt.Errorf("permission %q has invalid AccessScope preset %q: %w", permission.Code, code, err)
			}
		}
	}
	return nil
}

package checker

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/pkg/ctxutil"
)

// IBoundaryChecker 能力边界校验器
type IBoundaryChecker interface {
	// ValidateActionScopes 校验一组动作代码是否在当前租户的授权范围内
	ValidateActionScopes(ctx context.Context, actions []string) error
	// GetForbiddenActions 返回给定 actions 中，当前租户无权使用的动作列表 (批量优化版)
	GetForbiddenActions(ctx context.Context, actions []string) ([]string, error)
}

type boundaryChecker struct {
	permRepo repository.IPermissionRepository
}

func NewBoundaryChecker(permRepo repository.IPermissionRepository) IBoundaryChecker {
	return &boundaryChecker{permRepo: permRepo}
}

func (c *boundaryChecker) ValidateActionScopes(ctx context.Context, actions []string) error {
	if ctxutil.GetTenantID(ctx).Int64() == ctxutil.SystemTenantID {
		return nil
	}

	if len(actions) == 0 {
		return nil
	}

	// 批量查询当前提交动作对应的元数据
	perms, err := c.permRepo.FindByActions(ctx, actions)
	if err != nil {
		return err
	}

	// 边界判定：普通租户严禁使用任何标记为 ScopeSystem 的权限点
	for _, p := range perms {
		if p.Scope == domain.ScopeSystem {
			return errs.ErrForbidden
		}
	}

	return nil
}

func (c *boundaryChecker) GetForbiddenActions(ctx context.Context, actions []string) ([]string, error) {
	if ctxutil.GetTenantID(ctx).Int64() == ctxutil.SystemTenantID || len(actions) == 0 {
		return nil, nil
	}

	perms, err := c.permRepo.FindByActions(ctx, actions)
	if err != nil {
		return nil, err
	}

	var forbidden []string
	for _, p := range perms {
		if p.Scope == domain.ScopeSystem {
			forbidden = append(forbidden, p.Code)
		}
	}

	return forbidden, nil
}

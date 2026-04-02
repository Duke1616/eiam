package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
)

// IPermissionRepository 权限映射仓库：管理能力码与物理资产的关联
type IPermissionRepository interface {
	// CreatePermission 注册一个新的逻辑权限码
	CreatePermission(ctx context.Context, p domain.Permission) (int64, error)
	// DeletePermission 删除某个权限码，并级联清理所有其绑定的资源记录
	DeletePermission(ctx context.Context, tenantId int64, id int64) error
	// GetByCode 根据能力码获取权限详情
	GetByCode(ctx context.Context, tenantId int64, code string) (domain.Permission, error)

	// BindResources 核心动作：将指定的物理资源 ID 批量绑定到能力码上
	BindResources(ctx context.Context, tenantId int64, permId int64, permCode string, resType domain.ResourceType, resIds []int64) error
	// FindCodesByResource 反查逻辑：物理资源(API/Menu)背后受哪些能力码保护
	FindCodesByResource(ctx context.Context, resType domain.ResourceType, resId int64) ([]string, error)
	// FindBindingsByPerm 发现逻辑：一个能力码包里装了哪些物理资源
	FindBindingsByPerm(ctx context.Context, permId int64) ([]domain.PermissionBinding, error)
}

type PermissionRepository struct {
	dao dao.IPermissionDAO
}

func NewPermissionRepository(dao dao.IPermissionDAO) IPermissionRepository {
	return &PermissionRepository{dao: dao}
}

func (r *PermissionRepository) CreatePermission(ctx context.Context, p domain.Permission) (int64, error) {
	return r.dao.Insert(ctx, dao.Permission{
		TenantId: p.TenantID,
		Code:     p.Code,
		Name:     p.Name,
		Desc:     p.Desc,
		Group:    p.Group,
		Status:   p.Status,
	})
}

func (r *PermissionRepository) GetByCode(ctx context.Context, tenantId int64, code string) (domain.Permission, error) {
	p, err := r.dao.GetByCode(ctx, tenantId, code)
	if err != nil {
		return domain.Permission{}, err
	}
	return domain.Permission{
		ID:       p.Id,
		TenantID: p.TenantId,
		Code:     p.Code,
		Name:     p.Name,
		Desc:     p.Desc,
		Group:    p.Group,
		Status:   p.Status,
	}, nil
}

func (r *PermissionRepository) BindResources(ctx context.Context, tenantId int64, permId int64, permCode string, resType domain.ResourceType, resIds []int64) error {
	bindings := make([]dao.PermissionBinding, 0, len(resIds))
	for _, rid := range resIds {
		bindings = append(bindings, dao.PermissionBinding{
			TenantId:     tenantId,
			PermId:       permId,
			PermCode:     permCode,
			ResourceType: string(resType),
			ResourceId:   rid,
		})
	}
	return r.dao.BindResource(ctx, bindings)
}

func (r *PermissionRepository) DeletePermission(ctx context.Context, tenantId int64, id int64) error {
	return r.dao.Delete(ctx, tenantId, id)
}

func (r *PermissionRepository) FindCodesByResource(ctx context.Context, resType domain.ResourceType, resId int64) ([]string, error) {
	bindings, err := r.dao.GetBindingsByRes(ctx, resType, resId)
	if err != nil {
		return nil, err
	}
	codes := make([]string, 0, len(bindings))
	for _, b := range bindings {
		codes = append(codes, b.PermCode)
	}
	return codes, nil
}

func (r *PermissionRepository) FindBindingsByPerm(ctx context.Context, permId int64) ([]domain.PermissionBinding, error) {
	bindings, err := r.dao.ListBindings(ctx, permId)
	if err != nil {
		return nil, err
	}
	res := make([]domain.PermissionBinding, 0, len(bindings))
	for _, b := range bindings {
		res = append(res, domain.PermissionBinding{
			ID:           b.Id,
			TenantID:     b.TenantId,
			PermID:       b.PermId,
			PermCode:     b.PermCode,
			ResourceType: domain.ResourceType(b.ResourceType),
			ResourceID:   b.ResourceId,
		})
	}
	return res, nil
}

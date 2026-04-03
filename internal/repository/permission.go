package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/ecodeclub/ekit/slice"
)

// IPermissionRepository 权限仓库：管理全局能力项及其绑定的物理资产
type IPermissionRepository interface {
	// CreatePermission 录入一个新的全局逻辑能力 (如 iam:user:view)
	CreatePermission(ctx context.Context, p domain.Permission) (int64, error)
	// DeletePermission 删除能力项并清理其下的资产绑定
	DeletePermission(ctx context.Context, id int64) error
	// GetByCode 获取能力项元数据
	GetByCode(ctx context.Context, code string) (domain.Permission, error)

	// BindResources 全局绑定接口：定义哪些物理 ID 属于这个功能码
	BindResources(ctx context.Context, permId int64, permCode string, resType domain.ResourceType, resIds []int64) error
	// FindCodesByResource 反查中心：通过物理资源定位功能逻辑码
	FindCodesByResource(ctx context.Context, resType domain.ResourceType, resId int64) ([]string, error)
	// FindBindingsByPerm 正查中心：查看一个功能码下聚合了哪些物理资源
	FindBindingsByPerm(ctx context.Context, permId int64) ([]domain.ResourceBinding, error)
}

type PermissionRepository struct {
	dao dao.IPermissionDAO
}

func NewPermissionRepository(dao dao.IPermissionDAO) IPermissionRepository {
	return &PermissionRepository{dao: dao}
}

func (r *PermissionRepository) CreatePermission(ctx context.Context, p domain.Permission) (int64, error) {
	return r.dao.Insert(ctx, dao.Permission{
		Code:   p.Code,
		Name:   p.Name,
		Desc:   p.Desc,
		Group:  p.Group,
		Status: p.Status,
	})
}

func (r *PermissionRepository) DeletePermission(ctx context.Context, id int64) error {
	return r.dao.Delete(ctx, id)
}

func (r *PermissionRepository) GetByCode(ctx context.Context, code string) (domain.Permission, error) {
	p, err := r.dao.GetByCode(ctx, code)
	if err != nil {
		return domain.Permission{}, err
	}
	return domain.Permission{
		ID:     p.Id,
		Code:   p.Code,
		Name:   p.Name,
		Desc:   p.Desc,
		Group:  p.Group,
		Status: p.Status,
	}, nil
}

func (r *PermissionRepository) BindResources(ctx context.Context, permId int64, permCode string, resType domain.ResourceType, resIds []int64) error {
	bindings := slice.Map(resIds, func(idx int, src int64) dao.PermissionBinding {
		return dao.PermissionBinding{
			PermId:       permId,
			PermCode:     permCode,
			ResourceType: resType.String(),
			ResourceId:   src,
		}
	})

	return r.dao.BindResources(ctx, bindings)
}

func (r *PermissionRepository) FindCodesByResource(ctx context.Context, resType domain.ResourceType, resId int64) ([]string, error) {
	bindings, err := r.dao.GetBindingsByRes(ctx, resType.String(), resId)

	return slice.Map(bindings, func(i int, src dao.PermissionBinding) string {
		return src.PermCode
	}), err
}

func (r *PermissionRepository) FindBindingsByPerm(ctx context.Context, permId int64) ([]domain.ResourceBinding, error) {
	bindings, err := r.dao.ListBindingsByPerm(ctx, permId)

	return slice.Map(bindings, func(i int, src dao.PermissionBinding) domain.ResourceBinding {
		return domain.ResourceBinding{
			ResourceType: domain.ResourceType(src.ResourceType),
			ResourceID:   src.ResourceId,
		}
	}), err
}

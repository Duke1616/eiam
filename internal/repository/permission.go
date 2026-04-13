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
	// BatchCreatePermission 批量录入全局逻辑能力项
	BatchCreatePermission(ctx context.Context, perms []domain.Permission) error
	// DeletePermission 删除能力项并清理其下的资产绑定
	DeletePermission(ctx context.Context, id int64) error
	// GetByCode 获取能力项元数据
	GetByCode(ctx context.Context, code string) (domain.Permission, error)
	// ListAllPermissions 获取全量能力项清单
	ListAllPermissions(ctx context.Context) ([]domain.Permission, error)

	// BindResources 全局绑定接口：定义哪些物理标识属于这个功能码
	BindResources(ctx context.Context, permId int64, permCode string, resURNs []string) error
	// BatchBindResources 批量执行资源染色逻辑 (高性能模式)
	BatchBindResources(ctx context.Context, bindings map[string][]string) error
	// FindCodesByResource 反查中心：通过物理资源 URN 定位功能逻辑码
	FindCodesByResource(ctx context.Context, resURN string) ([]string, error)
	// FindBindingsByPerm 正查中心：查看一个功能码下聚合了哪些物理资源
	FindBindingsByPerm(ctx context.Context, permId int64) ([]domain.ResourceBinding, error)
	// FindCodesByResourceURNs 批量反向检索，返回 map[ResourceURN][]PermCode
	FindCodesByResourceURNs(ctx context.Context, resURNs []string) (map[string][]string, error)

	// SyncResourceBindings 同步资源绑定关系 (Full-Sync 模式)
	SyncResourceBindings(ctx context.Context, allURNs []string, mappings map[string][]string) error
	// ListCasbinRules 直接查询 casbin_rule 表 (用于业务化列表展现)
	ListCasbinRules(ctx context.Context, tid string, pageNum, pageSize int64) ([]dao.CasbinRule, int64, error)
}

type PermissionRepository struct {
	dao dao.IPermissionDAO
}

func NewPermissionRepository(dao dao.IPermissionDAO) IPermissionRepository {
	return &PermissionRepository{dao: dao}
}

func (r *PermissionRepository) CreatePermission(ctx context.Context, p domain.Permission) (int64, error) {
	return r.dao.Insert(ctx, dao.Permission{
		Service: p.Service,
		Code:    p.Code,
		Name:    p.Name,
		Group:   p.Group,
		Needs:   p.Needs,
	})
}

func (r *PermissionRepository) BatchCreatePermission(ctx context.Context, perms []domain.Permission) error {
	daoPerms := make([]dao.Permission, 0, len(perms))
	for _, p := range perms {
		daoPerms = append(daoPerms, dao.Permission{
			Service: p.Service,
			Code:    p.Code,
			Name:    p.Name,
			Group:   p.Group,
			Needs:   p.Needs,
		})
	}

	return r.dao.BatchInsert(ctx, daoPerms)
}

func (r *PermissionRepository) DeletePermission(ctx context.Context, id int64) error {
	return r.dao.Delete(ctx, id)
}

func (r *PermissionRepository) GetByCode(ctx context.Context, code string) (domain.Permission, error) {
	p, err := r.dao.GetByCode(ctx, code)
	if err != nil {
		return domain.Permission{}, err
	}
	return r.toDomain(p), nil
}

func (r *PermissionRepository) ListAllPermissions(ctx context.Context) ([]domain.Permission, error) {
	perms, err := r.dao.ListAll(ctx)
	if err != nil {
		return nil, err
	}

	return slice.Map(perms, func(i int, src dao.Permission) domain.Permission {
		return r.toDomain(src)
	}), nil
}

func (r *PermissionRepository) toDomain(p dao.Permission) domain.Permission {
	return domain.Permission{
		ID:      p.Id,
		Service: p.Service,
		Code:    p.Code,
		Name:    p.Name,
		Group:   p.Group,
		Needs:   p.Needs,
	}
}

func (r *PermissionRepository) BindResources(ctx context.Context, permId int64, permCode string, resURNs []string) error {
	bindings := slice.Map(resURNs, func(idx int, src string) dao.PermissionBinding {
		return dao.PermissionBinding{
			PermId:      permId,
			PermCode:    permCode,
			ResourceURN: src,
		}
	})

	return r.dao.BindResources(ctx, bindings)
}

func (r *PermissionRepository) BatchBindResources(ctx context.Context, bindings map[string][]string) error {
	// 1. 预加载权限索引，批量获取 PermID (避免在循环中触发 GetByCode)
	all, err := r.ListAllPermissions(ctx)
	if err != nil {
		return err
	}
	permMap := make(map[string]int64, len(all))
	for _, p := range all {
		permMap[p.Code] = p.ID
	}

	// 2. 打平数据结构，转化为 DAO 的单次批量录入协议
	daoBindings := make([]dao.PermissionBinding, 0)
	for code, urns := range bindings {
		id := permMap[code]
		for _, urn := range urns {
			daoBindings = append(daoBindings, dao.PermissionBinding{
				PermId:      id,
				PermCode:    code,
				ResourceURN: urn,
			})
		}
	}

	if len(daoBindings) == 0 {
		return nil
	}

	return r.dao.BindResources(ctx, daoBindings)
}

func (r *PermissionRepository) FindCodesByResource(ctx context.Context, resURN string) ([]string, error) {
	bindings, err := r.dao.GetBindingsByRes(ctx, resURN)

	return slice.Map(bindings, func(i int, src dao.PermissionBinding) string {
		return src.PermCode
	}), err
}

func (r *PermissionRepository) FindBindingsByPerm(ctx context.Context, permId int64) ([]domain.ResourceBinding, error) {
	bindings, err := r.dao.ListBindingsByPerm(ctx, permId)

	return slice.Map(bindings, func(i int, src dao.PermissionBinding) domain.ResourceBinding {
		return domain.ResourceBinding{
			TenantId:    src.TenantId,
			ResourceURN: src.ResourceURN,
		}
	}), err
}

func (r *PermissionRepository) FindCodesByResourceURNs(ctx context.Context, resURNs []string) (map[string][]string, error) {
	bindings, err := r.dao.ListBindingsByResURNs(ctx, resURNs)
	if err != nil {
		return nil, err
	}

	res := make(map[string][]string)
	for _, b := range bindings {
		res[b.ResourceURN] = append(res[b.ResourceURN], b.PermCode)
	}
	return res, nil
}

func (r *PermissionRepository) SyncResourceBindings(ctx context.Context, allURNs []string, mappings map[string][]string) error {
	// 1. 预加载权限索引，批量获取 PermID
	all, err := r.ListAllPermissions(ctx)
	if err != nil {
		return err
	}
	permMap := make(map[string]int64, len(all))
	for _, p := range all {
		permMap[p.Code] = p.ID
	}

	// 2. 打平数据结构
	daoBindings := make([]dao.PermissionBinding, 0)
	for code, urns := range mappings {
		id := permMap[code]
		for _, urn := range urns {
			daoBindings = append(daoBindings, dao.PermissionBinding{
				PermId:      id,
				PermCode:    code,
				ResourceURN: urn,
			})
		}
	}

	return r.dao.SyncResourceBindings(ctx, allURNs, daoBindings)
}

func (r *PermissionRepository) ListCasbinRules(ctx context.Context, tid string, pageNum, pageSize int64) ([]dao.CasbinRule, int64, error) {
	return r.dao.ListCasbinRules(ctx, tid, pageNum, pageSize)
}

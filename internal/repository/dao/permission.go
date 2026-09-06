package dao

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Duke1616/eiam/pkg/pbac"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Permission 逻辑权限能力定义 (全平台标准，不分租户)
type Permission struct {
	Id                 int64                    `gorm:"type:bigint;primaryKey;autoIncrement;comment:'权限ID'"`
	Service            string                   `gorm:"type:varchar(64);not null;default:'';index:idx_perm_service_source;comment:'所属服务'"`
	Source             string                   `gorm:"type:varchar(128);not null;default:'';index:idx_perm_service_source;comment:'资产来源'"`
	Code               string                   `gorm:"type:varchar(128);not null;uniqueIndex:uniq_idx_perm_code;comment:'逻辑权限码'"`
	Name               string                   `gorm:"type:varchar(255);not null;comment:'能力名称'"`
	Group              string                   `gorm:"type:varchar(64);not null;default:'';comment:'所属分组'"`
	Needs              []string                 `gorm:"serializer:json;type:text;comment:'依赖能力项'"`
	Scope              string                   `gorm:"type:varchar(32);not null;default:'tenant';comment:'权限作用域'"`
	Sort               int                      `gorm:"type:int;not null;default:0;comment:'注册顺序权重'"`
	AccessScopePresets []pbac.AccessScopePreset `gorm:"serializer:json;type:text;comment:'AccessScope 可视化模板'"`
	Ctime              int64                    `gorm:"type:bigint;not null;comment:'创建时间'"`
	Utime              int64                    `gorm:"type:bigint;not null;comment:'更新时间'"`
	Status             uint8                    `gorm:"type:tinyint;not null;default:1;comment:'状态 1-正常 2-孤儿'"`
}

const (
	PermissionStatusActive uint8 = 1
	PermissionStatusOrphan uint8 = 2
)

// PermissionBinding 物理资产关联表 (全局通用映射)
// 决定了 "iam:user:view" 这个 Code 映射了哪些 API 或 菜单
type PermissionBinding struct {
	Id          int64  `gorm:"type:bigint;primaryKey;autoIncrement;comment:'映射ID'"`
	PermId      int64  `gorm:"type:bigint;not null;index:idx_perm_id;comment:'权限能力ID'"`
	PermCode    string `gorm:"type:varchar(128);not null;uniqueIndex:uniq_idx_perm_res_tenant;comment:'权限能力码'"`
	TenantId    int64  `gorm:"type:bigint;not null;uniqueIndex:uniq_idx_perm_res_tenant;comment:'租户标识'" eiam:"shared"`
	ResourceURN string `gorm:"type:varchar(256);not null;uniqueIndex:uniq_idx_perm_res_tenant;comment:'资源唯一标识'"`
}

// CasbinRule Casbin 存储规则模型
type CasbinRule struct {
	ID    int64  `gorm:"primaryKey;autoIncrement"`
	Ptype string `gorm:"size:100;index"`
	V0    string `gorm:"size:100;index"`
	V1    string `gorm:"size:100;index"`
	V2    string `gorm:"size:100;index"` // 域 (Tenant ID)
	V3    string `gorm:"size:100;index"`
	V4    string `gorm:"size:100;index"`
	V5    string `gorm:"size:100;index"`
}

func (CasbinRule) TableName() string {
	return "casbin_rule"
}

// IPermissionDAO 定义了逻辑权限能力项与物理资产绑定的底层持久化接口。
//go:generate mockgen -package=daomocks -destination=./mocks/permission.mock.go github.com/Duke1616/eiam/internal/repository/dao IPermissionDAO
type IPermissionDAO interface {
	// Insert 录入单个逻辑权限定义，返回自增 ID
	Insert(ctx context.Context, p Permission) (int64, error)
	// BatchInsert 批量录入逻辑权限定义；以 code 为唯一键，发生冲突时更新元数据并将状态重置为 Active
	BatchInsert(ctx context.Context, perms []Permission) error
	// Delete 根据主键 ID 删除权限记录，并在同一事务内物理级联删除关联的资源绑定
	Delete(ctx context.Context, id int64) error
	// GetByCode 根据权限码精确获取权限定义，未找到时返回 gorm.ErrRecordNotFound
	GetByCode(ctx context.Context, code string) (Permission, error)
	// ListAll 查询系统中全部逻辑权限定义
	ListAll(ctx context.Context) ([]Permission, error)

	// BindResources 批量写入物理资源绑定关系；以 (perm_code, tenant_id, resource_urn) 为唯一索引进行 Upsert
	BindResources(ctx context.Context, bindings []PermissionBinding) error
	// GetBindingsByRes 根据物理资产 URN 查询其关联的全部权限绑定记录
	GetBindingsByRes(ctx context.Context, resURN string) ([]PermissionBinding, error)
	// ListBindingsByPerm 根据逻辑权限 ID 查询其关联的全部物理资产绑定记录
	ListBindingsByPerm(ctx context.Context, permId int64) ([]PermissionBinding, error)
	// ListBindingsByResURNs 批量根据物理资产 URN 列表查询对应的全部权限绑定记录
	ListBindingsByResURNs(ctx context.Context, resURNs []string) ([]PermissionBinding, error)
	// ListMenuBindings 查询所有菜单类型的资源绑定关系（前缀为 eiam:menu:）
	ListMenuBindings(ctx context.Context) ([]PermissionBinding, error)

	// SyncResourceBindings 在事务中全量同步资源绑定关系：先删除 resURNs 的已有绑定，再写入新的映射
	SyncResourceBindings(ctx context.Context, resURNs []string, bindings []PermissionBinding) error
	// ListCasbinRules 分页查询指定租户下的 Casbin 继承规则（ptype='g' 且 v2=tid），支持按主体/角色前缀与关键字过滤
	ListCasbinRules(ctx context.Context, tid, offset, limit int64, v0Prefix, v1Prefix, keyword string) ([]CasbinRule, int64, error)
	// FindByActions 根据 Action 列表查询权限定义，支持通配符后缀（如 iam:user:*）模糊匹配及精确匹配
	FindByActions(ctx context.Context, actions []string) ([]Permission, error)
	// FindParentsByNeeds 反向拓扑查询：查找 needs 依赖项中包含任一指定权限码的父级权限码列表
	FindParentsByNeeds(ctx context.Context, codes []string) ([]string, error)
	// CountByService 按服务名分组统计逻辑权限数量
	CountByService(ctx context.Context) ([]ServiceCount, error)
	// DeletePermissionsByServiceAndCodes 物理删除指定服务与来源下不在 codes 列表中的权限记录
	DeletePermissionsByServiceAndCodes(ctx context.Context, service, source string, codes []string) error
	// MarkPermissionsAsOrphan 将指定服务与来源下不在 codes 列表中的权限标记为孤儿状态
	MarkPermissionsAsOrphan(ctx context.Context, service, source string, codes []string) error
	// DeleteBindingsByPermCodes 批量删除指定权限码的资源绑定记录，自动排除菜单类资源（避免影响全局菜单染色）
	DeleteBindingsByPermCodes(ctx context.Context, codes []string) error
	// Transaction 在事务上下文中执行业务逻辑，通过 context 隐式传递事务连接
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error
}

type ServiceCount struct {
	Service string
	Count   int64
}

type PermissionDAO struct {
	db *gorm.DB
}

func (d *PermissionDAO) getDB(ctx context.Context) *gorm.DB {
	tx, ok := ctx.Value(txKey{}).(*gorm.DB)
	if ok {
		return tx.WithContext(ctx)
	}
	return d.db.WithContext(ctx)
}

func NewPermissionDAO(db *gorm.DB) IPermissionDAO {
	return &PermissionDAO{db: db}
}

func (d *PermissionDAO) Insert(ctx context.Context, p Permission) (int64, error) {
	now := time.Now().UnixMilli()
	p.Ctime = now
	p.Utime = now
	err := d.getDB(ctx).Create(&p).Error
	return p.Id, err
}

func (d *PermissionDAO) BatchInsert(ctx context.Context, perms []Permission) error {
	if len(perms) == 0 {
		return nil
	}

	now := time.Now().UnixMilli()
	for i := range perms {
		perms[i].Ctime = now
		perms[i].Utime = now
		perms[i].Status = PermissionStatusActive
	}

	return d.getDB(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "code"}},
		DoUpdates: clause.AssignmentColumns([]string{"service", "source", "name", "group", "needs", "scope", "utime", "status", "sort", "access_scope_presets"}),
	}).CreateInBatches(perms, 100).Error
}

func (d *PermissionDAO) Delete(ctx context.Context, id int64) error {
	return d.Transaction(ctx, func(txCtx context.Context) error {
		if err := d.getDB(txCtx).Where("id = ?", id).Delete(&Permission{}).Error; err != nil {
			return err
		}
		return d.getDB(txCtx).Where("perm_id = ?", id).Delete(&PermissionBinding{}).Error
	})
}

func (d *PermissionDAO) GetByCode(ctx context.Context, code string) (Permission, error) {
	var p Permission
	err := d.getDB(ctx).Where("code = ?", code).First(&p).Error
	return p, err
}

func (d *PermissionDAO) ListAll(ctx context.Context) ([]Permission, error) {
	var res []Permission
	err := d.getDB(ctx).Find(&res).Error
	return res, err
}

func (d *PermissionDAO) BindResources(ctx context.Context, bindings []PermissionBinding) error {
	if len(bindings) == 0 {
		return nil
	}

	// 分批写入，防止 SQL 占位符超限
	return d.getDB(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "perm_code"}, {Name: "tenant_id"}, {Name: "resource_urn"}},
		DoUpdates: clause.AssignmentColumns([]string{"perm_id"}),
	}).CreateInBatches(bindings, 100).Error
}

func (d *PermissionDAO) GetBindingsByRes(ctx context.Context, resURN string) ([]PermissionBinding, error) {
	var res []PermissionBinding
	err := d.getDB(ctx).Where("resource_urn = ?", resURN).Find(&res).Error
	return res, err
}

func (d *PermissionDAO) ListBindingsByPerm(ctx context.Context, permId int64) ([]PermissionBinding, error) {
	var res []PermissionBinding
	err := d.getDB(ctx).Where("perm_id = ?", permId).Find(&res).Error
	return res, err
}

func (d *PermissionDAO) ListBindingsByResURNs(ctx context.Context, resURNs []string) ([]PermissionBinding, error) {
	var res []PermissionBinding
	if len(resURNs) == 0 {
		return res, nil
	}
	err := d.getDB(ctx).Where("resource_urn IN ?", resURNs).Find(&res).Error
	return res, err
}

func (d *PermissionDAO) ListMenuBindings(ctx context.Context) ([]PermissionBinding, error) {
	var res []PermissionBinding
	err := d.getDB(ctx).Where("resource_urn LIKE ?", "eiam:menu:%").Find(&res).Error
	return res, err
}

func (d *PermissionDAO) SyncResourceBindings(ctx context.Context, resURNs []string, bindings []PermissionBinding) error {
	return d.Transaction(ctx, func(txCtx context.Context) error {
		if len(resURNs) > 0 {
			if err := d.getDB(txCtx).Where("resource_urn IN ?", resURNs).Delete(&PermissionBinding{}).Error; err != nil {
				return err
			}
		}
		if len(bindings) > 0 {
			// 分批写入，防止 SQL 占位符超限
			return d.getDB(txCtx).Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "perm_code"}, {Name: "tenant_id"}, {Name: "resource_urn"}},
				DoUpdates: clause.AssignmentColumns([]string{"perm_id"}),
			}).CreateInBatches(bindings, 100).Error
		}
		return nil
	})
}

func (d *PermissionDAO) ListCasbinRules(ctx context.Context, tid, offset, limit int64, v0Prefix, v1Prefix, keyword string) ([]CasbinRule, int64, error) {
	var (
		res   []CasbinRule
		total int64
	)

	db := d.getDB(ctx).Model(&CasbinRule{}).
		Where("ptype = 'g' AND v2 = ?", tid)

	if v0Prefix != "" {
		db = db.Where("v0 LIKE ?", v0Prefix+"%")
	}

	if v1Prefix != "" {
		db = db.Where("v1 LIKE ?", v1Prefix+"%")
	}

	if keyword != "" {
		kw := "%" + keyword + "%"
		db = db.Where("(v0 LIKE ? OR v1 LIKE ?)", kw, kw)
	}

	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	err := db.Limit(int(limit)).Offset(int(offset)).Order("id DESC").Find(&res).Error
	return res, total, err
}

func (d *PermissionDAO) FindByActions(ctx context.Context, actions []string) ([]Permission, error) {
	var res []Permission
	if len(actions) == 0 {
		return res, nil
	}

	db := d.getDB(ctx).Model(&Permission{})
	query := d.getDB(ctx)

	hasWildcard := false
	for _, action := range actions {
		if strings.HasSuffix(action, "*") {
			hasWildcard = true
			prefix := strings.TrimSuffix(action, "*")
			query = query.Or("code LIKE ?", prefix+"%")
		}
	}

	if hasWildcard {
		query = query.Or("code IN ?", actions)
		db = db.Where(query)
	} else {
		db = db.Where("code IN ?", actions)
	}

	err := db.Find(&res).Error
	return res, err
}

func (d *PermissionDAO) FindParentsByNeeds(ctx context.Context, codes []string) ([]string, error) {
	if len(codes) == 0 {
		return nil, nil
	}

	var res []string
	query := d.getDB(ctx).Model(&Permission{})
	for _, code := range codes {
		query = query.Or("JSON_CONTAINS(needs, ?)", fmt.Sprintf("\"%s\"", code))
	}

	err := query.Pluck("code", &res).Error
	return res, err
}

func (d *PermissionDAO) CountByService(ctx context.Context) ([]ServiceCount, error) {
	var res []ServiceCount
	err := d.getDB(ctx).Model(&Permission{}).
		Select("service, count(*) as count").
		Group("service").
		Scan(&res).Error
	return res, err
}

func (d *PermissionDAO) DeletePermissionsByServiceAndCodes(ctx context.Context, service, source string, codes []string) error {
	if service == "" {
		return nil
	}
	if len(codes) == 0 {
		return d.getDB(ctx).Where("service = ? AND source = ?", service, source).Delete(&Permission{}).Error
	}
	return d.getDB(ctx).Where("service = ? AND source = ? AND code NOT IN ?", service, source, codes).Delete(&Permission{}).Error
}

func (d *PermissionDAO) MarkPermissionsAsOrphan(ctx context.Context, service, source string, codes []string) error {
	if len(codes) == 0 {
		return d.getDB(ctx).Model(&Permission{}).Where("service = ? AND source = ?", service, source).Update("status", PermissionStatusOrphan).Error
	}
	return d.getDB(ctx).Model(&Permission{}).Where("service = ? AND source = ? AND code NOT IN ?", service, source, codes).Update("status", PermissionStatusOrphan).Error
}

func (d *PermissionDAO) DeleteBindingsByPermCodes(ctx context.Context, codes []string) error {
	if len(codes) == 0 {
		return nil
	}
	// NOTE: 在清空或重新录入某微服务权限对应的物理资产关联时，必须排除菜单类型的绑定关系。
	// 菜单与功能权限的染色关系（resource_urn 以前缀 eiam:menu: 区分）是由 eiam 仓库的 YAML 独立
	// 全量对齐维护的，在此处清除会导致微服务重启时菜单权限莫名丢失。
	return d.getDB(ctx).
		Where("perm_code IN ?", codes).
		Where("resource_urn NOT LIKE ?", "eiam:menu:%").
		Delete(&PermissionBinding{}).Error
}

func (d *PermissionDAO) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		newCtx := context.WithValue(ctx, txKey{}, tx)
		return fn(newCtx)
	})
}

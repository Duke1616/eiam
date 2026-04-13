package dao

import (
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Permission 逻辑权限能力定义 (全平台标准，不分租户)
type Permission struct {
	Id      int64    `gorm:"type:bigint;primaryKey;autoIncrement;comment:'权限ID'"`
	Service string   `gorm:"type:varchar(64);not null;default:'';index:idx_perm_service;comment:'所属服务'"`
	Code    string   `gorm:"type:varchar(128);not null;uniqueIndex:uniq_idx_perm_code;comment:'逻辑权限码'"`
	Name    string   `gorm:"type:varchar(255);not null;comment:'能力名称'"`
	Group   string   `gorm:"type:varchar(64);not null;default:'';comment:'所属分组'"`
	Needs   []string `gorm:"serializer:json;type:text;comment:'依赖能力项'"`
	Ctime   int64    `gorm:"type:bigint;not null;comment:'创建时间'"`
	Utime   int64    `gorm:"type:bigint;not null;comment:'更新时间'"`
}

// PermissionBinding 物理资产关联表 (全局通用映射)
// 决定了 "iam:user:view" 这个 Code 映射了哪些 API 或 菜单
type PermissionBinding struct {
	Id          int64  `gorm:"type:bigint;primaryKey;autoIncrement;comment:'映射ID'"`
	PermId      int64  `gorm:"type:bigint;not null;index:idx_perm_id;comment:'权限能力ID'"`
	PermCode    string `gorm:"type:varchar(128);not null;uniqueIndex:uniq_idx_perm_res_tenant;comment:'权限能力码'"`
	TenantId    int64  `gorm:"type:bigint;not null;uniqueIndex:uniq_idx_perm_res_tenant;comment:'租户标识';eiam:'shared'"`
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

type IPermissionDAO interface {
	Insert(ctx context.Context, p Permission) (int64, error)
	BatchInsert(ctx context.Context, perms []Permission) error
	Delete(ctx context.Context, id int64) error
	GetByCode(ctx context.Context, code string) (Permission, error)
	ListAll(ctx context.Context) ([]Permission, error)

	// BindResources 批量关联物理资产 (基于唯一索引实现幂等，不重复插入)
	BindResources(ctx context.Context, bindings []PermissionBinding) error
	// GetBindingsByRes 反查：查看物理标识归属哪些能力码
	GetBindingsByRes(ctx context.Context, resURN string) ([]PermissionBinding, error)
	// ListBindingsByPerm 正查：查看能力项下的全部资产
	ListBindingsByPerm(ctx context.Context, permId int64) ([]PermissionBinding, error)
	// ListBindingsByResURNs 批量反查：查看一组 URN 分别归属哪些能力码
	ListBindingsByResURNs(ctx context.Context, resURNs []string) ([]PermissionBinding, error)

	// SyncResourceBindings 同步物理资产与功能码的映射关系 (基于 URN 的 Full-Sync)
	SyncResourceBindings(ctx context.Context, resURNs []string, bindings []PermissionBinding) error
	// ListCasbinRules 查询 Casbin 关系规则 (带分页)
	ListCasbinRules(ctx context.Context, tid string, pageNum, pageSize int64) ([]CasbinRule, int64, error)
}

type PermissionDAO struct {
	db *gorm.DB
}

func NewPermissionDAO(db *gorm.DB) IPermissionDAO {
	return &PermissionDAO{db: db}
}

func (d *PermissionDAO) Insert(ctx context.Context, p Permission) (int64, error) {
	now := time.Now().UnixMilli()
	p.Ctime = now
	p.Utime = now
	err := d.db.WithContext(ctx).Create(&p).Error
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
	}

	return d.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "code"}},
		DoUpdates: clause.AssignmentColumns([]string{"name", "group", "needs", "utime"}),
	}).Create(&perms).Error
}

func (d *PermissionDAO) Delete(ctx context.Context, id int64) error {
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ?", id).Delete(&Permission{}).Error; err != nil {
			return err
		}
		return tx.Where("perm_id = ?", id).Delete(&PermissionBinding{}).Error
	})
}

func (d *PermissionDAO) GetByCode(ctx context.Context, code string) (Permission, error) {
	var p Permission
	err := d.db.WithContext(ctx).Where("code = ?", code).First(&p).Error
	return p, err
}

func (d *PermissionDAO) ListAll(ctx context.Context) ([]Permission, error) {
	var res []Permission
	err := d.db.WithContext(ctx).Find(&res).Error
	return res, err
}

func (d *PermissionDAO) BindResources(ctx context.Context, bindings []PermissionBinding) error {
	if len(bindings) == 0 {
		return nil
	}

	return d.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "perm_code"}, {Name: "tenant_id"}, {Name: "resource_urn"}},
		DoUpdates: clause.AssignmentColumns([]string{"perm_id"}),
	}).Create(&bindings).Error
}

func (d *PermissionDAO) GetBindingsByRes(ctx context.Context, resURN string) ([]PermissionBinding, error) {
	var res []PermissionBinding
	err := d.db.WithContext(ctx).Where("resource_urn = ?", resURN).Find(&res).Error
	return res, err
}

func (d *PermissionDAO) ListBindingsByPerm(ctx context.Context, permId int64) ([]PermissionBinding, error) {
	var res []PermissionBinding
	err := d.db.WithContext(ctx).Where("perm_id = ?", permId).Find(&res).Error
	return res, err
}

func (d *PermissionDAO) ListBindingsByResURNs(ctx context.Context, resURNs []string) ([]PermissionBinding, error) {
	var res []PermissionBinding
	err := d.db.WithContext(ctx).Where("resource_urn IN ?", resURNs).Find(&res).Error
	return res, err
}

func (d *PermissionDAO) SyncResourceBindings(ctx context.Context, resURNs []string, bindings []PermissionBinding) error {
	// ... (代码逻辑保持不变)
	return d.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if len(resURNs) > 0 {
			if err := tx.Where("resource_urn IN ?", resURNs).Delete(&PermissionBinding{}).Error; err != nil {
				return err
			}
		}
		if len(bindings) > 0 {
			return tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "perm_code"}, {Name: "tenant_id"}, {Name: "resource_urn"}},
				DoUpdates: clause.AssignmentColumns([]string{"perm_id"}),
			}).Create(&bindings).Error
		}
		return nil
	})
}

func (d *PermissionDAO) ListCasbinRules(ctx context.Context, tid string, pageNum, pageSize int64) ([]CasbinRule, int64, error) {
	var (
		res   []CasbinRule
		total int64
	)

	// 只查询 g 类型的记录（即主体与角色/策略的继承关系）
	db := d.db.WithContext(ctx).Model(&CasbinRule{}).
		Where("ptype = 'g'").
		Where("v2 = ? OR v2 = '0'", tid) // 匹配当前租户 + 全局公共关系

	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (pageNum - 1) * pageSize
	err := db.Limit(int(pageSize)).Offset(int(offset)).Order("id DESC").Find(&res).Error
	return res, total, err
}

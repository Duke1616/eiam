package dao

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"gorm.io/gorm"
)

// Role 角色持久化实体
type Role struct {
	Id             int64                            `gorm:"type:bigint;primaryKey;autoIncrement;comment:'角色ID'"`
	TenantId       int64                            `gorm:"type:bigint;not null;default:0;uniqueIndex:uniq_idx_tenant_role_code,priority:1;comment:'租户ID 1 为系统全局角色'" eiam:"shared:type=1"`
	Name           string                           `gorm:"type:varchar(255);not null;comment:'角色名称'"`
	Code           string                           `gorm:"type:varchar(255);not null;uniqueIndex:uniq_idx_tenant_role_code,priority:2;comment:'角色标识码'"`
	Desc           string                           `gorm:"type:varchar(512);not null;default:'';comment:'角色描述信息'"`
	Type           uint8                            `gorm:"type:tinyint;not null;default:2;comment:'角色类型: 1-系统预设, 2-自定义'"`
	InlinePolicies sqlx.JSONColumn[[]domain.Policy] `gorm:"type:json;column:inline_policies;comment:'内联权限策略列表'"`
	Ctime          int64                            `gorm:"comment:'创建时间'"`
	Utime          int64                            `gorm:"comment:'更新时间'"`
}

// IRoleDAO 角色数据库操作接口
type IRoleDAO interface {
	// Insert 插入新角色
	Insert(ctx context.Context, r Role) (int64, error)
	// Update 更新角色基础属性
	Update(ctx context.Context, r Role) (int64, error)
	// List 分页查询角色，依赖 Context 自动隔离
	List(ctx context.Context, offset, limit int64) ([]Role, error)
	// Count 统计角色总数
	Count(ctx context.Context) (int64, error)
	// Search 模糊查询
	Search(ctx context.Context, keyword string, offset, limit int64) ([]Role, error)
	// CountByKeyword 按关键字统计
	CountByKeyword(ctx context.Context, keyword string) (int64, error)
	// GetByCode 根据角色代码获取角色
	GetByCode(ctx context.Context, code string) (Role, error)
	// ListByIncludeCodes 根据给定的一组代码批量查询
	ListByIncludeCodes(ctx context.Context, codes []string) ([]Role, error)
	// UpdateInlinePolicies 更新角色关联的内联权限策略列表
	UpdateInlinePolicies(ctx context.Context, code string, policies []domain.Policy) error
	// GetAttachedRolesWithFilter 联表分页获取指定主体关联的角色详情，支持关键词过滤
	GetAttachedRolesWithFilter(ctx context.Context, username string, tid, offset, limit int64, keyword string) ([]Role, int64, error)
	// Delete 删除角色
	Delete(ctx context.Context, id int64) error
	// DeleteByIDs 批量删除角色
	DeleteByIDs(ctx context.Context, ids []int64) (int64, error)
	// GetByID 根据 ID 获取角色
	GetByID(ctx context.Context, id int64) (Role, error)
	// FindByIDs 根据 ID 批量获取角色
	FindByIDs(ctx context.Context, ids []int64) ([]Role, error)
	// CheckRolesUsage 批量检查角色是否正在被使用 (存在 Casbin 关联)
	CheckRolesUsage(ctx context.Context, roleCodes []string, tid int64) ([]string, error)
}

type RoleDAO struct {
	db *gorm.DB
}

// NewRoleDAO 创建角色数据库操作实例
func NewRoleDAO(db *gorm.DB) IRoleDAO {
	return &RoleDAO{db: db}
}

func (d *RoleDAO) Insert(ctx context.Context, r Role) (int64, error) {
	now := time.Now().UnixMilli()
	r.Ctime = now
	r.Utime = now
	err := d.db.WithContext(ctx).Create(&r).Error
	return r.Id, err
}

func (d *RoleDAO) Update(ctx context.Context, r Role) (int64, error) {
	res := d.db.WithContext(ctx).Model(&Role{}).
		Where("id = ?", r.Id).Updates(map[string]interface{}{
		"name":  r.Name,
		"desc":  r.Desc,
		"utime": time.Now().UnixMilli(),
	})
	return res.RowsAffected, res.Error
}

func (d *RoleDAO) List(ctx context.Context, offset, limit int64) ([]Role, error) {
	var roles []Role
	err := d.db.WithContext(ctx).
		Offset(int(offset)).Limit(int(limit)).Order("tenant_id ASC, ctime DESC").Find(&roles).Error
	return roles, err
}

func (d *RoleDAO) Count(ctx context.Context) (int64, error) {
	var total int64
	err := d.db.WithContext(ctx).Model(&Role{}).Count(&total).Error
	return total, err
}

func (d *RoleDAO) CountByKeyword(ctx context.Context, keyword string) (int64, error) {
	var total int64
	db := d.db.WithContext(ctx).Model(&Role{})

	if keyword != "" {
		kw := "%" + keyword + "%"
		db = db.Where("name LIKE ? OR code LIKE ?", kw, kw)
	}

	err := db.Count(&total).Error
	return total, err
}

func (d *RoleDAO) Search(ctx context.Context, keyword string, offset, limit int64) ([]Role, error) {
	var roles []Role

	db := d.db.WithContext(ctx).Model(&Role{})

	if keyword != "" {
		kw := "%" + keyword + "%"
		db = db.Where("name LIKE ? OR code LIKE ?", kw, kw)
	}

	err := db.Offset(int(offset)).Limit(int(limit)).
		Order("tenant_id ASC, ctime DESC").Find(&roles).Error
	return roles, err
}

func (d *RoleDAO) GetByCode(ctx context.Context, code string) (Role, error) {
	var r Role
	err := d.db.WithContext(ctx).Where("code = ?", code).
		Order("tenant_id DESC").First(&r).Error
	return r, err
}

func (d *RoleDAO) ListByIncludeCodes(ctx context.Context, codes []string) ([]Role, error) {
	var roles []Role
	if len(codes) == 0 {
		return roles, nil
	}
	err := d.db.WithContext(ctx).Where("code IN ?", codes).
		Order("tenant_id DESC, ctime DESC").Find(&roles).Error
	return roles, err
}

func (d *RoleDAO) UpdateInlinePolicies(ctx context.Context, code string, policies []domain.Policy) error {
	return d.db.WithContext(ctx).Model(&Role{}).
		Where("code = ?", code).Updates(map[string]interface{}{
		"inline_policies": sqlx.JSONColumn[[]domain.Policy]{
			Val:   policies,
			Valid: true,
		},
		"utime": time.Now().UnixMilli(),
	}).Error
}

func (d *RoleDAO) GetAttachedRolesWithFilter(ctx context.Context, username string, tid, offset, limit int64, keyword string) ([]Role, int64, error) {
	var (
		rs    []Role
		total int64
	)

	// 1. 构造内部关联子查询：从 casbin_rule 中获取该主体关联该角色的时间 (存放在 v3)
	// 使用 CAST 将字符串转换为整数，处理可能存在的小数点问题
	subQueryExpr := d.db.Table("casbin_rule").
		Select("CAST(v3 AS SIGNED)").
		Where("REPLACE(casbin_rule.v1, ?, '') = role.code", domain.PrefixRole).
		Where("ptype = 'g' AND v0 = ? AND v2 = ?", domain.UserSubject(username), tid)

	// 2. 构造过滤子查询：找出该主体关联的所有角色代码
	filterSubQuery := d.db.Table("casbin_rule").
		Select("REPLACE(v1, ?, '')", domain.PrefixRole).
		Where("ptype = 'g' AND v0 = ? AND v2 = ?", domain.UserSubject(username), tid)

	// 3. 主查询：构建基础过滤查询（不带 Select 关联子查询，专用于 Count 计算）
	baseQuery := d.db.WithContext(ctx).Model(&Role{}).
		Where("code IN (?)", filterSubQuery)

	if keyword != "" {
		kw := "%" + keyword + "%"
		baseQuery = baseQuery.Where("(name LIKE ? OR code LIKE ?)", kw, kw)
	}

	err := baseQuery.Count(&total).Error
	if err != nil || total == 0 {
		return nil, 0, err
	}

	// 4. 将关联子查询结果注入 Select 字段，执行具体的分页与 Order 详情获取
	err = baseQuery.Select("*, (?) AS ctime", subQueryExpr).
		Offset(int(offset)).Limit(int(limit)).
		Order("ctime DESC").Find(&rs).Error

	return rs, total, err
}

func (d *RoleDAO) Delete(ctx context.Context, id int64) error {
	return d.db.WithContext(ctx).Delete(&Role{}, id).Error
}

func (d *RoleDAO) DeleteByIDs(ctx context.Context, ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	res := d.db.WithContext(ctx).Delete(&Role{}, ids)
	return res.RowsAffected, res.Error
}

func (d *RoleDAO) GetByID(ctx context.Context, id int64) (Role, error) {
	var r Role
	err := d.db.WithContext(ctx).Where("id = ?", id).First(&r).Error
	return r, err
}

func (d *RoleDAO) FindByIDs(ctx context.Context, ids []int64) ([]Role, error) {
	var rs []Role
	if len(ids) == 0 {
		return rs, nil
	}
	err := d.db.WithContext(ctx).Where("id IN ?", ids).Find(&rs).Error
	return rs, err
}

func (d *RoleDAO) CheckRolesUsage(ctx context.Context, roleCodes []string, tid int64) ([]string, error) {
	var usedCodes []string
	if len(roleCodes) == 0 {
		return usedCodes, nil
	}

	// 构造 Casbin 角色标识列表
	// 注意：这里需要与 domain.RoleSubject 的逻辑一致，通常是 "role:" + code
	// 为了解耦，我们在上层转换好传入，或者在这里处理。
	// 这里直接查 casbin_rule 表中 v1 匹配 roleCodes 且 v2 匹配租户的记录
	err := d.db.WithContext(ctx).Table("casbin_rule").
		Where("ptype = 'g' AND v1 IN ? AND v2 = ?", roleCodes, tid).
		Distinct("v1").
		Pluck("v1", &usedCodes).Error

	return usedCodes, err
}

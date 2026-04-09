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
	Id       int64                            `gorm:"type:bigint;primaryKey;autoIncrement;comment:'角色ID'"`
	TenantId int64                            `gorm:"type:bigint;not null;default:0;uniqueIndex:uniq_idx_tenant_role_code,priority:1;comment:'租户ID，0为系统全局角色';eiam:'shared'"`
	Name     string                           `gorm:"type:varchar(255);not null;comment:'角色名称'"`
	Code     string                           `gorm:"type:varchar(255);not null;uniqueIndex:uniq_idx_tenant_role_code,priority:2;comment:'角色标识码'"`
	Desc     string                           `gorm:"type:varchar(512);not null;default:'';comment:'角色描述信息'"`
	Status   bool                             `gorm:"type:tinyint;not null;default:1;comment:'状态: 1-启用, 0-禁用'"`
	Type     uint8                            `gorm:"type:tinyint;not null;default:2;comment:'角色类型: 1-系统预设, 2-自定义'"`
	Policies sqlx.JSONColumn[[]domain.Policy] `gorm:"type:json;column:policies;comment:'绑定权限策略列表 (AWS 风格)'"`
	Ctime    int64                            `gorm:"comment:'创建时间'"`
	Utime    int64                            `gorm:"comment:'更新时间'"`
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
	// GetByCode 根据角色代码获取角色
	GetByCode(ctx context.Context, code string) (Role, error)
	// ListByIncludeCodes 根据给定的一组代码批量查询
	ListByIncludeCodes(ctx context.Context, codes []string) ([]Role, error)
	// UpdatePolicies 更新角色关联的权限策略列表
	UpdatePolicies(ctx context.Context, code string, policies []domain.Policy) error
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
		"name":   r.Name,
		"desc":   r.Desc,
		"status": r.Status,
		"utime":  time.Now().UnixMilli(),
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

func (d *RoleDAO) GetByCode(ctx context.Context, code string) (Role, error) {
	var r Role
	err := d.db.WithContext(ctx).Where("code = ?", code).
		Order("tenant_id DESC").First(&r).Error
	return r, err
}

func (d *RoleDAO) ListByIncludeCodes(ctx context.Context, codes []string) ([]Role, error) {
	var roles []Role
	err := d.db.WithContext(ctx).Where("code IN ?", codes).
		Order("tenant_id DESC, ctime DESC").Find(&roles).Error
	return roles, err
}

func (d *RoleDAO) UpdatePolicies(ctx context.Context, code string, policies []domain.Policy) error {
	return d.db.WithContext(ctx).Model(&Role{}).
		Where("code = ?", code).Updates(map[string]interface{}{
		"policies": sqlx.JSONColumn[[]domain.Policy]{
			Val:   policies,
			Valid: true,
		},
		"utime": time.Now().UnixMilli(),
	}).Error
}

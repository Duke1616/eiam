package dao

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"gorm.io/gorm"
)

// Policy 权限策略持久化实体
type Policy struct {
	Id       int64                               `gorm:"type:bigint;primaryKey;autoIncrement;comment:'策略ID'"`
	TenantId int64                               `gorm:"type:bigint;not null;default:0;index:idx_tenant_policy;comment:'租户ID，0为系统全局策略'"`
	Name     string                              `gorm:"type:varchar(255);not null;comment:'策略显示名称'"`
	Code     string                              `gorm:"type:varchar(255);not null;uniqueIndex:uniq_policy_code;comment:'策略唯一标识码'"`
	Desc     string                              `gorm:"type:varchar(512);not null;default:'';comment:'策略描述信息'"`
	Type     uint8                               `gorm:"type:tinyint;not null;default:1;comment:'策略类型: 1-系统预设, 2-自定义'"`
	Document sqlx.JSONColumn[[]domain.Statement] `gorm:"type:json;not null;comment:'策略语句文档的内容'"`
	Ctime    int64                               `gorm:"comment:'创建时间'"`
	Utime    int64                               `gorm:"comment:'更新时间'"`
}

// RolePolicyAttachment 角色与策略的关联表 (实现多对多)
type RolePolicyAttachment struct {
	Id       int64  `gorm:"primaryKey;autoIncrement"`
	RoleCode string `gorm:"type:varchar(255);not null;index:idx_role_policy;comment:'角色代码'"`
	PolyCode string `gorm:"type:varchar(255);not null;index:idx_role_policy;comment:'策略代码'"`
	Ctime    int64
}

// IPolicyDAO 权限策略数据库操作接口
type IPolicyDAO interface {
	// Insert 插入新的策略文档
	Insert(ctx context.Context, p Policy) (int64, error)
	// GetByCode 根据策略标识码获取策略详情
	GetByCode(ctx context.Context, code string) (Policy, error)
	// List 分页获取策略
	List(ctx context.Context, offset, limit int64) ([]Policy, error)
	// Count 统计策略总数
	Count(ctx context.Context) (int64, error)
	// Update 更新策略详情
	Update(ctx context.Context, p Policy) error
	// BindToRole 建立角色与托管策略的关联关系 (幂等)
	BindToRole(ctx context.Context, roleCode, polyCode string) error
	// UnbindFromRole 解除角色与托管策略的关联关系
	UnbindFromRole(ctx context.Context, roleCode, polyCode string) error
	// GetCodesByRole 获取指定角色关联的所有托管策略代码列表
	GetCodesByRole(ctx context.Context, roleCode string) ([]string, error)
	// GetCodesByRoleCodes 批量获取多个角色关联的所有托管策略代码映射
	GetCodesByRoleCodes(ctx context.Context, roleCodes []string) ([]RolePolicyAttachment, error)
	// GetByCodes 批量获取策略详情
	GetByCodes(ctx context.Context, codes []string) ([]Policy, error)
	// GetByTypes 按类型批量获取策略详情
	GetByTypes(ctx context.Context, types []domain.PolicyType) ([]Policy, error)
}

type policyDAO struct {
	db *gorm.DB
}

func NewPolicyDAO(db *gorm.DB) IPolicyDAO {
	return &policyDAO{db: db}
}

func (d *policyDAO) Insert(ctx context.Context, p Policy) (int64, error) {
	now := time.Now().UnixMilli()
	p.Ctime = now
	p.Utime = now
	err := d.db.WithContext(ctx).Create(&p).Error
	return p.Id, err
}

func (d *policyDAO) GetByCode(ctx context.Context, code string) (Policy, error) {
	var p Policy
	err := d.db.WithContext(ctx).Where("code = ?", code).First(&p).Error
	return p, err
}

func (d *policyDAO) List(ctx context.Context, offset, limit int64) ([]Policy, error) {
	var ps []Policy
	err := d.db.WithContext(ctx).Model(&Policy{}).
		Offset(int(offset)).Limit(int(limit)).Find(&ps).Error
	return ps, err
}

func (d *policyDAO) Count(ctx context.Context) (int64, error) {
	var total int64
	err := d.db.WithContext(ctx).Model(&Policy{}).Count(&total).Error
	return total, err
}

func (d *policyDAO) Update(ctx context.Context, p Policy) error {
	return d.db.WithContext(ctx).Model(&Policy{}).
		Where("code = ?", p.Code).
		Select("name", "desc", "document", "utime").
		Updates(Policy{
			Name:     p.Name,
			Desc:     p.Desc,
			Document: p.Document,
			Utime:    time.Now().UnixMilli(),
		}).Error
}

func (d *policyDAO) GetCodesByRoleCodes(ctx context.Context, roleCodes []string) ([]RolePolicyAttachment, error) {
	var attachments []RolePolicyAttachment
	err := d.db.WithContext(ctx).
		Model(&RolePolicyAttachment{}).
		Where("role_code IN ?", roleCodes).
		Find(&attachments).Error
	return attachments, err
}

func (d *policyDAO) BindToRole(ctx context.Context, roleCode, polyCode string) error {
	return d.db.WithContext(ctx).FirstOrCreate(&RolePolicyAttachment{
		RoleCode: roleCode,
		PolyCode: polyCode,
		Ctime:    time.Now().UnixMilli(),
	}, RolePolicyAttachment{RoleCode: roleCode, PolyCode: polyCode}).Error
}

func (d *policyDAO) UnbindFromRole(ctx context.Context, roleCode, polyCode string) error {
	return d.db.WithContext(ctx).
		Where("role_code = ? AND poly_code = ?", roleCode, polyCode).
		Delete(&RolePolicyAttachment{}).Error
}

func (d *policyDAO) GetCodesByRole(ctx context.Context, roleCode string) ([]string, error) {
	var codes []string
	err := d.db.WithContext(ctx).
		Model(&RolePolicyAttachment{}).
		Where("role_code = ?", roleCode).
		Pluck("poly_code", &codes).Error
	return codes, err
}

func (d *policyDAO) GetByCodes(ctx context.Context, codes []string) ([]Policy, error) {
	var policies []Policy
	err := d.db.WithContext(ctx).
		Where("code IN ?", codes).
		Find(&policies).Error
	return policies, err
}

func (d *policyDAO) GetByTypes(ctx context.Context, types []domain.PolicyType) ([]Policy, error) {
	var policies []Policy
	err := d.db.WithContext(ctx).
		Where("type IN ?", types).
		Find(&policies).Error
	return policies, err
}

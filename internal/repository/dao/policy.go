package dao

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Policy 权限策略持久化实体
type Policy struct {
	Id       int64                               `gorm:"type:bigint;primaryKey;autoIncrement;comment:'策略ID'"`
	TenantId int64                               `gorm:"type:bigint;not null;default:0;index:idx_tenant_policy;comment:'租户ID，0为系统全局策略';eiam:'shared'"`
	Name     string                              `gorm:"type:varchar(255);not null;comment:'策略显示名称'"`
	Code     string                              `gorm:"type:varchar(255);not null;uniqueIndex:uniq_policy_code;comment:'策略唯一标识码'"`
	Desc     string                              `gorm:"type:varchar(512);not null;default:'';comment:'策略描述信息'"`
	Type     uint8                               `gorm:"type:tinyint;not null;default:1;comment:'策略类型: 1-系统预设, 2-自定义'"`
	Document sqlx.JSONColumn[[]domain.Statement] `gorm:"type:json;not null;comment:'策略语句文档的内容'"`
	Ctime    int64                               `gorm:"comment:'创建时间'"`
	Utime    int64                               `gorm:"comment:'更新时间'"`
}

// PolicyAssignment 策略分配关联表 (支持用户和角色统一授权)
type PolicyAssignment struct {
	Id         int64  `gorm:"primaryKey;autoIncrement"`
	TenantId   int64  `gorm:"type:bigint;not null;uniqueIndex:uniq_subject_policy;comment:'租户ID';eiam:'shared'"`
	SubType    string `gorm:"type:varchar(20);not null;uniqueIndex:uniq_subject_policy;comment:'主体类型: user, role'"`
	SubCode    string `gorm:"type:varchar(255);not null;uniqueIndex:uniq_subject_policy;comment:'主体标识 (用户名或角色代码)'"`
	PolicyCode string `gorm:"type:varchar(255);not null;uniqueIndex:uniq_subject_policy;comment:'策略代码'"`
	Ctime      int64
}

// BatchBindResult 批量绑定结果元数据
type BatchBindResult struct {
	Total    int64 // 预期处理总数
	Inserted int64 // 实际新插入的数量
	Ignored  int64 // 因冲突被忽略的数量
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
	// Search 关键词与类型搜索
	Search(ctx context.Context, offset, limit int64, keyword string, policyType uint8) ([]Policy, error)
	// CountBySearch 关键词与类型搜索总数
	CountBySearch(ctx context.Context, keyword string, policyType uint8) (int64, error)
	// Update 更新策略详情
	Update(ctx context.Context, p Policy) error
	// Bind 建立主体与策略的关联关系 (幂等)
	Bind(ctx context.Context, subType, subCode, policyCode string) error
	// Unbind 解除主体与策略的关联关系
	Unbind(ctx context.Context, subType, subCode, policyCode string) error
	// GetCodesBySubject 获取指定主体关联的所有策略代码列表
	GetCodesBySubject(ctx context.Context, subType, subCode string) ([]string, error)
	// GetCodesBySubjectWithPagination 分页获取指定主体关联的策略代码列表
	GetCodesBySubjectWithPagination(ctx context.Context, subType, subCode string, offset, limit int64) ([]string, int64, error)
	// GetAttachedPoliciesWithFilter 联表分页获取指定主体关联的策略详情，支持关键词与类型过滤
	GetAttachedPoliciesWithFilter(ctx context.Context, subType, subCode string, offset, limit int64, keyword string, policyType uint8) ([]Policy, int64, error)
	// GetCodesBySubjects 批量获取多个主体代码关联的所有策略映射
	GetCodesBySubjects(ctx context.Context, subjects []domain.Subject) ([]PolicyAssignment, error)
	// GetByCodes 批量获取策略详情
	GetByCodes(ctx context.Context, codes []string) ([]Policy, error)
	// GetByTypes 按类型批量获取策略详情
	GetByTypes(ctx context.Context, types []domain.PolicyType) ([]Policy, error)
	// ListAssignments 分页获取策略分配关系
	ListAssignments(ctx context.Context, offset, limit int64, subType string, keyword string) ([]PolicyAssignment, int64, error)
	// BatchBind 批量绑定策略到多个主体
	BatchBind(ctx context.Context, assignments []PolicyAssignment) (BatchBindResult, error)
	// CountAssignmentsByPolicyCodes 批量获取策略关联的数量
	CountAssignmentsByPolicyCodes(ctx context.Context, codes []string) (map[string]int64, error)
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

func (d *policyDAO) Search(ctx context.Context, offset, limit int64, keyword string, policyType uint8) ([]Policy, error) {
	var ps []Policy
	query := d.db.WithContext(ctx).Model(&Policy{})
	if keyword != "" {
		query = query.Where("name LIKE ? OR code LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}
	if policyType != 0 {
		query = query.Where("type = ?", policyType)
	}
	err := query.Offset(int(offset)).Limit(int(limit)).Find(&ps).Error
	return ps, err
}

func (d *policyDAO) CountBySearch(ctx context.Context, keyword string, policyType uint8) (int64, error) {
	var total int64
	query := d.db.WithContext(ctx).Model(&Policy{})
	if keyword != "" {
		query = query.Where("name LIKE ? OR code LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}
	if policyType != 0 {
		query = query.Where("type = ?", policyType)
	}
	err := query.Count(&total).Error
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

func (d *policyDAO) GetCodesBySubjects(ctx context.Context, subjects []domain.Subject) ([]PolicyAssignment, error) {
	if len(subjects) == 0 {
		return nil, nil
	}
	// 使用元组 IN 查询，更优雅且性能更好
	values := make([][]any, len(subjects))
	for i, sub := range subjects {
		values[i] = []any{sub.Type, sub.ID}
	}

	var assignments []PolicyAssignment
	err := d.db.WithContext(ctx).
		Model(&PolicyAssignment{}).
		Where("(sub_type, sub_code) IN ?", values).
		Find(&assignments).Error

	return assignments, err
}

func (d *policyDAO) Bind(ctx context.Context, subType, subCode, policyCode string) error {
	return d.db.WithContext(ctx).FirstOrCreate(&PolicyAssignment{
		SubType:    subType,
		SubCode:    subCode,
		PolicyCode: policyCode,
		Ctime:      time.Now().UnixMilli(),
	}, PolicyAssignment{SubType: subType, SubCode: subCode, PolicyCode: policyCode}).Error
}

func (d *policyDAO) Unbind(ctx context.Context, subType, subCode, policyCode string) error {
	return d.db.WithContext(ctx).
		Where("sub_type = ? AND sub_code = ? AND policy_code = ?", subType, subCode, policyCode).
		Delete(&PolicyAssignment{}).Error
}

func (d *policyDAO) GetCodesBySubjectWithPagination(ctx context.Context, subType, subCode string, offset, limit int64) ([]string, int64, error) {
	var (
		codes []string
		total int64
	)
	query := d.db.WithContext(ctx).Model(&PolicyAssignment{}).
		Where("sub_type = ? AND sub_code = ?", subType, subCode)

	err := query.Count(&total).Error
	if err != nil || total == 0 {
		return nil, 0, err
	}

	err = query.Offset(int(offset)).Limit(int(limit)).Pluck("policy_code", &codes).Error
	return codes, total, err
}

func (d *policyDAO) GetCodesBySubject(ctx context.Context, subType, subCode string) ([]string, error) {
	var codes []string
	err := d.db.WithContext(ctx).
		Model(&PolicyAssignment{}).
		Where("sub_type = ? AND sub_code = ?", subType, subCode).
		Pluck("policy_code", &codes).Error
	return codes, err
}

func (d *policyDAO) GetAttachedPoliciesWithFilter(ctx context.Context, subType, subCode string, offset, limit int64, keyword string, policyType uint8) ([]Policy, int64, error) {
	var (
		ps    []Policy
		total int64
	)

	// 1. 构造子查询：从 policy_assignment 中找出关联的策略代码
	// 使用 Model(&PolicyAssignment{}) 让 GORM 自动处理表名映射
	subQuery := d.db.Model(&PolicyAssignment{}).
		Select("policy_code").
		Where("sub_type = ? AND sub_code = ?", subType, subCode)

	// 2. 主查询：基于子查询结果筛选策略详情
	query := d.db.WithContext(ctx).Model(&Policy{}).
		Where("code IN (?)", subQuery)

	if keyword != "" {
		query = query.Where("(name LIKE ? OR code LIKE ?)", "%"+keyword+"%", "%"+keyword+"%")
	}
	if policyType != 0 {
		query = query.Where("type = ?", policyType)
	}

	err := query.Count(&total).Error
	if err != nil || total == 0 {
		return nil, 0, err
	}

	err = query.Offset(int(offset)).Limit(int(limit)).Find(&ps).Error
	return ps, total, err
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

func (d *policyDAO) ListAssignments(ctx context.Context, offset, limit int64, subType string, keyword string) ([]PolicyAssignment, int64, error) {
	var (
		assignments []PolicyAssignment
		total       int64
	)
	query := d.db.WithContext(ctx).Model(&PolicyAssignment{})

	if subType != "" {
		query = query.Where("sub_type = ?", subType)
	}
	if keyword != "" {
		query = query.Where("sub_code LIKE ? OR policy_code LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}

	err := query.Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Offset(int(offset)).Limit(int(limit)).Find(&assignments).Error
	return assignments, total, err
}

func (d *policyDAO) BatchBind(ctx context.Context, assignments []PolicyAssignment) (BatchBindResult, error) {
	if len(assignments) == 0 {
		return BatchBindResult{}, nil
	}

	now := time.Now().UnixMilli()
	for i := range assignments {
		assignments[i].Ctime = now
	}

	// 批量插入，冲突时忽略
	result := d.db.WithContext(ctx).Clauses(clause.OnConflict{
		DoNothing: true,
	}).CreateInBatches(assignments, 100)

	return BatchBindResult{
		Total:    int64(len(assignments)),
		Inserted: result.RowsAffected,
		Ignored:  int64(len(assignments)) - result.RowsAffected,
	}, result.Error
}

func (d *policyDAO) CountAssignmentsByPolicyCodes(ctx context.Context, codes []string) (map[string]int64, error) {
	if len(codes) == 0 {
		return make(map[string]int64), nil
	}

	type resultStruct struct {
		PolicyCode string
		Count      int64
	}

	var rs []resultStruct
	err := d.db.WithContext(ctx).Model(&PolicyAssignment{}).
		Where("policy_code IN ?", codes).
		Select("policy_code, COUNT(*) as count").
		Group("policy_code").
		Scan(&rs).Error

	if err != nil {
		return nil, err
	}

	res := make(map[string]int64, len(rs))
	for _, r := range rs {
		res[r.PolicyCode] = r.Count
	}
	return res, nil
}

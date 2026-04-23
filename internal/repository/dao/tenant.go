package dao

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/pkg/ctxutil"
	"gorm.io/gorm"
)

// ITenantDAO 租户数据持久化接口
type ITenantDAO interface {
	// Create 创建新租户详情
	Create(ctx context.Context, t Tenant) (int64, error)
	// FindById 根据主键 ID 查询租户详情
	FindById(ctx context.Context, id int64) (Tenant, error)
	// FindByCode 根据唯一标识代码查询租户详情
	FindByCode(ctx context.Context, code string) (Tenant, error)
	// FindAll 分页获取系统内所有租户列表
	FindAll(ctx context.Context, offset, limit int64) ([]Tenant, error)
	// Count 统计系统内租户总数
	Count(ctx context.Context) (int64, error)
	// Update 更新租户名称、域名及状态等信息
	Update(ctx context.Context, t Tenant) error
	// Delete 物理删除租户记录
	Delete(ctx context.Context, id int64) error
	// BatchCreate 批量创建新租户
	BatchCreate(ctx context.Context, ts []Tenant) ([]Tenant, error)

	// --- Membership 持久化 ---

	// InsertMembership 插入用户与租户的关联映射（入驻记录）
	InsertMembership(ctx context.Context, m Membership) error
	// BatchInsertMemberships 批量插入用户与租户的关联映射
	BatchInsertMemberships(ctx context.Context, ms []Membership) error
	// AddMembership 插入单条成员关联逻辑
	AddMembership(ctx context.Context, userID, tenantID int64) error
	// DeleteMembership 移除用户与租户的关联映射
	DeleteMembership(ctx context.Context, tenantID, userID int64) error
	// GetMembership 精确查询特定租户下特定用户的入驻信息
	GetMembership(ctx context.Context, tenantId, userId int64) (Membership, error)
	// GetMembershipByUserId 查询用户在当前操作语境下的入驻信息
	GetMembershipByUserId(ctx context.Context, userId int64) (Membership, error)
	// FindMembershipsByUserIds 批量检索一组用户的入驻关联记录
	FindMembershipsByUserIds(ctx context.Context, userIds []int64) ([]Membership, error)
	// FindTenantsByIDs 根据 ID 列表批量检索租户详情
	FindTenantsByIDs(ctx context.Context, ids []int64) ([]Tenant, error)
	// FindTenantIDsByUserId 查询指定用户所属的所有租户 ID 列表
	FindTenantIDsByUserId(ctx context.Context, userId int64) ([]int64, error)
	// GetAttachedTenantsWithFilter 分页模糊查询关联用户的租户
	GetAttachedTenantsWithFilter(ctx context.Context, userID, tid, offset, limit int64, keyword string) ([]Tenant, int64, error)
}

type TenantDAO struct {
	db *gorm.DB
}

func NewTenantDAO(db *gorm.DB) ITenantDAO {
	return &TenantDAO{db: db}
}

type Tenant struct {
	ID     int64  `gorm:"primaryKey;autoIncrement"`
	Name   string `gorm:"type:varchar(255)"`
	Code   string `gorm:"uniqueIndex;type:varchar(64)"`
	Domain string `gorm:"type:varchar(255)"`
	Status int    `gorm:"type:tinyint"`
	Ctime  int64  `gorm:"comment:'创建时间'"`
	Utime  int64  `gorm:"comment:'更新时间'"`
}

// Membership 映射表：仅代表入驻契约，不存储动态授权。
type Membership struct {
	ID       int64 `gorm:"primaryKey;autoIncrement"`
	TenantID int64 `gorm:"index:idx_tenant_user"`
	UserID   int64 `gorm:"index:idx_tenant_user"`
	Ctime    int64 `gorm:"comment:'创建时间'"`
}

func (m Membership) TableName() string {
	return "membership"
}

func (d *TenantDAO) Create(ctx context.Context, t Tenant) (int64, error) {
	now := time.Now().UnixMilli()
	t.Ctime = now
	t.Utime = now
	err := d.db.WithContext(ctx).Create(&t).Error
	return t.ID, err
}

func (d *TenantDAO) BatchCreate(ctx context.Context, ts []Tenant) ([]Tenant, error) {
	now := time.Now().UnixMilli()
	for i := range ts {
		ts[i].Ctime = now
		ts[i].Utime = now
	}
	err := d.db.WithContext(ctx).Create(&ts).Error
	return ts, err
}

func (d *TenantDAO) InsertMembership(ctx context.Context, m Membership) error {
	m.Ctime = time.Now().UnixMilli()
	return d.db.WithContext(ctx).Create(&m).Error
}

func (d *TenantDAO) BatchInsertMemberships(ctx context.Context, ms []Membership) error {
	now := time.Now().UnixMilli()
	for i := range ms {
		ms[i].Ctime = now
	}
	return d.db.WithContext(ctx).Create(&ms).Error
}

func (d *TenantDAO) AddMembership(ctx context.Context, userID, tenantID int64) error {
	return d.db.WithContext(ctx).Create(&Membership{
		UserID:   userID,
		TenantID: tenantID,
		Ctime:    time.Now().UnixMilli(),
	}).Error
}

func (d *TenantDAO) DeleteMembership(ctx context.Context, tenantID, userID int64) error {
	return d.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Delete(&Membership{}).Error
}

func (d *TenantDAO) GetMembership(ctx context.Context, tenantId, userId int64) (Membership, error) {
	var m Membership
	err := d.db.WithContext(ctx).Where("tenant_id = ? AND user_id = ?", tenantId, userId).First(&m).Error
	return m, err
}

func (d *TenantDAO) GetMembershipByUserId(ctx context.Context, userId int64) (Membership, error) {
	var m Membership
	err := d.db.WithContext(ctx).Where("user_id = ?", userId).First(&m).Error
	return m, err
}

func (d *TenantDAO) FindMembershipsByUserIds(ctx context.Context, userIds []int64) ([]Membership, error) {
	var ms []Membership
	if len(userIds) == 0 {
		return ms, nil
	}
	err := d.db.WithContext(ctx).Where("user_id IN ?", userIds).Find(&ms).Error
	return ms, err
}

func (d *TenantDAO) FindById(ctx context.Context, id int64) (Tenant, error) {
	var t Tenant
	err := d.db.WithContext(ctx).Where("id = ?", id).First(&t).Error
	return t, err
}

func (d *TenantDAO) FindByCode(ctx context.Context, code string) (Tenant, error) {
	var t Tenant
	err := d.db.WithContext(ctx).Where("code = ?", code).First(&t).Error
	return t, err
}

func (d *TenantDAO) FindAll(ctx context.Context, offset, limit int64) ([]Tenant, error) {
	var ts []Tenant
	err := d.db.WithContext(ctx).Offset(int(offset)).Limit(int(limit)).Find(&ts).Error
	return ts, err
}

func (d *TenantDAO) Count(ctx context.Context) (int64, error) {
	var count int64
	err := d.db.WithContext(ctx).Model(&Tenant{}).Count(&count).Error
	return count, err
}

func (d *TenantDAO) Update(ctx context.Context, t Tenant) error {
	return d.db.WithContext(ctx).Model(&t).Where("id = ?", t.ID).Updates(map[string]any{
		"name":   t.Name,
		"code":   t.Code,
		"domain": t.Domain,
		"status": t.Status,
		"utime":  time.Now().UnixMilli(),
	}).Error
}

func (d *TenantDAO) Delete(ctx context.Context, id int64) error {
	return d.db.WithContext(ctx).Delete(&Tenant{}, id).Error
}

func (d *TenantDAO) FindTenantIDsByUserId(ctx context.Context, userId int64) ([]int64, error) {
	var ms []Membership
	err := d.db.WithContext(ctx).Select("tenant_id").Where("user_id = ?", userId).Find(&ms).Error
	if err != nil {
		return nil, err
	}

	ids := make([]int64, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.TenantID)
	}
	return ids, nil
}

func (d *TenantDAO) FindTenantsByIDs(ctx context.Context, ids []int64) ([]Tenant, error) {
	var ts []Tenant
	err := d.db.WithContext(ctx).Where("id IN ?", ids).Find(&ts).Error
	return ts, err
}

func (d *TenantDAO) GetAttachedTenantsWithFilter(ctx context.Context, userID, tid, offset, limit int64, keyword string) ([]Tenant, int64, error) {
	var (
		ts    []Tenant
		total int64
	)

	// 1. 构造内部关联子查询：获取该用户入驻该租户的时间
	subQueryExpr := d.db.Model(&Membership{}).
		Select("CAST(ctime AS SIGNED)").
		Where("membership.tenant_id = tenant.id").
		Where("membership.user_id = ?", userID)

	// 2. 将子查询注入主查询：直接覆盖到 tenant 的 ctime 字段中
	query := d.db.WithContext(ctx).Model(&Tenant{}).
		Select("*, (?) AS ctime", subQueryExpr)

	// 构造子查询，用于过滤出该用户有关联记录的租户 ID
	subQuery := d.db.WithContext(ctx).Model(&Membership{}).
		Select("tenant_id").
		Where("user_id = ?", userID)

	// 业务隔离逻辑：
	// 1. 如果是普通租户管理员，只能查询该用户在“当前租户”下的入驻记录。
	// 2. 如果是系统全局管理员 (SystemTenantID)，则允许跨租户查看该用户加入的所有空间。
	if tid != ctxutil.SystemTenantID {
		subQuery = subQuery.Where("tenant_id = ?", tid)
	}

	// 将子查询结果作为过滤条件
	query = query.Where("id IN (?)", subQuery)

	// 支持按租户名称或编码进行模糊搜索
	if keyword != "" {
		kw := "%" + keyword + "%"
		query = query.Where("(name LIKE ? OR code LIKE ?)", kw, kw)
	}

	err := query.Count(&total).Error
	if err != nil || total == 0 {
		return nil, 0, err
	}

	// 按照“关联时间 (ctime)”倒序排列，确保用户最近加入的租户排在最前面
	err = query.Offset(int(offset)).Limit(int(limit)).
		Order("ctime DESC").Find(&ts).Error

	return ts, total, err
}

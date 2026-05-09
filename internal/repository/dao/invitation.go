package dao

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/pkg/sqlx"
	"gorm.io/gorm"
)

type Invitation struct {
	Id              int64                     `gorm:"primaryKey;autoIncrement"`
	TenantId        int64                     `gorm:"type:bigint;not null;index;comment:'租户ID'"`
	InviterId       int64                     `gorm:"type:bigint;not null;comment:'发起人UID'"`
	Code            string                    `gorm:"type:varchar(64);not null;uniqueIndex;comment:'随机邀请短码'"`
	RoleCodes       sqlx.JSONColumn[[]string] `gorm:"type:json;comment:'自动赋予的角色代码'"`
	MaxUses         int                       `gorm:"type:int;not null;default:0;comment:'最大使用次数, 0不限'"`
	UsedCount       int                       `gorm:"type:int;not null;default:0;comment:'已使用次数'"`
	ExpireAt        int64                     `gorm:"comment:'过期时间'"`
	Status          uint8                     `gorm:"type:tinyint;not null;default:1;comment:'状态: 1-待使用, 2-已失效'"`
	RequireApproval bool                      `gorm:"type:tinyint(1);not null;default:0;comment:'是否需要审批'"`
	Ctime           int64
	Utime           int64
	DeletedAt       gorm.DeletedAt `gorm:"index"`
}

type JoinRequest struct {
	Id             int64                     `gorm:"primaryKey;autoIncrement"`
	TenantId       int64                     `gorm:"type:bigint;not null;index;comment:'租户ID'"`
	UserId         int64                     `gorm:"type:bigint;not null;index;comment:'申请人UID'"`
	InvitationCode string                    `gorm:"type:varchar(64);not null;comment:'邀请特征码'"`
	RoleCodes      sqlx.JSONColumn[[]string] `gorm:"type:json;comment:'预设角色代码'"`
	Status         uint8                     `gorm:"type:tinyint;not null;default:1;comment:'状态: 1-审批中, 2-通过, 3-驳回'"`
	Ctime          int64
	Utime          int64
}

type IInvitationDAO interface {
	// Insert 插入新邀请码记录
	Insert(ctx context.Context, inv Invitation) (int64, error)
	// GetByCode 根据邀请码获取详情
	GetByCode(ctx context.Context, code string) (Invitation, error)
	// IncrUsedCount 原子增加使用次数（数据库端）
	IncrUsedCount(ctx context.Context, code string) error
	// UpdateUsedCount 覆盖更新使用次数（用于缓存同步）
	UpdateUsedCount(ctx context.Context, code string, count int) error
	// UpdateStatus 更新邀请码状态
	UpdateStatus(ctx context.Context, code string, status uint8) error
	// ListByTenant 分页查询租户下的邀请码列表
	ListByTenant(ctx context.Context, tenantID int64, offset, limit int) ([]Invitation, error)
	// CountByTenant 统计租户下的邀请码总数
	CountByTenant(ctx context.Context, tenantID int64) (int64, error)
	// Delete 软删除邀请码记录
	Delete(ctx context.Context, tenantID int64, code string) error

	// InsertJoinRequest 插入新的入驻申请
	InsertJoinRequest(ctx context.Context, req JoinRequest) (int64, error)
	// ListJoinRequests 分页获取待处理申请列表
	ListJoinRequests(ctx context.Context, tenantID int64, offset, limit int) ([]JoinRequest, error)
	// CountJoinRequests 统计待处理申请总数
	CountJoinRequests(ctx context.Context, tenantID int64) (int64, error)
	// GetJoinRequestByID 根据 ID 获取申请记录
	GetJoinRequestByID(ctx context.Context, id int64) (JoinRequest, error)
	// UpdateJoinRequestStatus 更新申请处理状态
	UpdateJoinRequestStatus(ctx context.Context, id int64, status uint8) error
}

type invitationDAO struct {
	db *gorm.DB
}

func NewInvitationDAO(db *gorm.DB) IInvitationDAO {
	return &invitationDAO{db: db}
}

func (d *invitationDAO) Insert(ctx context.Context, inv Invitation) (int64, error) {
	now := time.Now().UnixMilli()
	inv.Ctime = now
	inv.Utime = now
	err := d.db.WithContext(ctx).Create(&inv).Error
	return inv.Id, err
}

func (d *invitationDAO) GetByCode(ctx context.Context, code string) (Invitation, error) {
	var res Invitation
	err := d.db.WithContext(ctx).Where("code = ?", code).First(&res).Error
	return res, err
}

func (d *invitationDAO) InsertJoinRequest(ctx context.Context, req JoinRequest) (int64, error) {
	now := time.Now().UnixMilli()
	req.Ctime = now
	req.Utime = now
	err := d.db.WithContext(ctx).Create(&req).Error
	return req.Id, err
}

func (d *invitationDAO) ListJoinRequests(ctx context.Context, tenantID int64, offset, limit int) ([]JoinRequest, error) {
	var res []JoinRequest
	err := d.db.WithContext(ctx).Where("tenant_id = ? AND status = ?", tenantID, 1).
		Offset(offset).Limit(limit).Order("id DESC").Find(&res).Error
	return res, err
}

func (d *invitationDAO) CountJoinRequests(ctx context.Context, tenantID int64) (int64, error) {
	var res int64
	err := d.db.WithContext(ctx).Model(&JoinRequest{}).Where("tenant_id = ? AND status = ?", tenantID, 1).Count(&res).Error
	return res, err
}

func (d *invitationDAO) GetJoinRequestByID(ctx context.Context, id int64) (JoinRequest, error) {
	var res JoinRequest
	err := d.db.WithContext(ctx).Where("id = ?", id).First(&res).Error
	return res, err
}

func (d *invitationDAO) UpdateJoinRequestStatus(ctx context.Context, id int64, status uint8) error {
	return d.db.WithContext(ctx).Model(&JoinRequest{}).Where("id = ?", id).
		Updates(map[string]any{
			"status": status,
			"utime":  time.Now().UnixMilli(),
		}).Error
}

func (d *invitationDAO) IncrUsedCount(ctx context.Context, code string) error {
	return d.db.WithContext(ctx).Model(&Invitation{}).
		Where("code = ?", code).
		Updates(map[string]any{
			"used_count": gorm.Expr("used_count + 1"),
			"utime":      time.Now().UnixMilli(),
		}).Error
}

func (d *invitationDAO) UpdateUsedCount(ctx context.Context, code string, count int) error {
	return d.db.WithContext(ctx).Model(&Invitation{}).
		Where("code = ?", code).
		Updates(map[string]any{
			"used_count": count,
			"utime":      time.Now().UnixMilli(),
		}).Error
}

func (d *invitationDAO) UpdateStatus(ctx context.Context, code string, status uint8) error {
	return d.db.WithContext(ctx).Model(&Invitation{}).
		Where("code = ?", code).
		Updates(map[string]any{
			"status": status,
			"utime":  time.Now().UnixMilli(),
		}).Error
}

func (d *invitationDAO) ListByTenant(ctx context.Context, tenantID int64, offset, limit int) ([]Invitation, error) {
	var res []Invitation
	err := d.db.WithContext(ctx).Where("tenant_id = ?", tenantID).
		Offset(offset).Limit(limit).Order("id DESC").Find(&res).Error
	return res, err
}

func (d *invitationDAO) CountByTenant(ctx context.Context, tenantID int64) (int64, error) {
	var res int64
	err := d.db.WithContext(ctx).Model(&Invitation{}).Where("tenant_id = ?", tenantID).Count(&res).Error
	return res, err
}

func (d *invitationDAO) Delete(ctx context.Context, tenantID int64, code string) error {
	return d.db.WithContext(ctx).Where("tenant_id = ? AND code = ?", tenantID, code).Delete(&Invitation{}).Error
}

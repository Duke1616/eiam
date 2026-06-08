package dao

import (
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Group struct {
	Id       int64  `gorm:"type:bigint;primaryKey;autoIncrement;comment:'用户组ID'"`
	TenantId int64  `gorm:"type:bigint;not null;default:0;uniqueIndex:uniq_idx_tenant_group_code,priority:1;comment:'租户ID'"`
	Name     string `gorm:"type:varchar(255);not null;comment:'用户组名称'"`
	Code     string `gorm:"type:varchar(255);not null;uniqueIndex:uniq_idx_tenant_group_code,priority:2;comment:'用户组标识码'"`
	Desc     string `gorm:"type:varchar(512);not null;default:'';comment:'描述'"`
	Ctime    int64  `gorm:"comment:'创建时间'"`
	Utime    int64  `gorm:"comment:'更新时间'"`
}

type UserGroup struct {
	Id       int64 `gorm:"type:bigint;primaryKey;autoIncrement"`
	TenantId int64 `gorm:"type:bigint;not null;default:0;uniqueIndex:uniq_idx_tenant_user_group,priority:1;comment:'租户ID'"`
	UserId   int64 `gorm:"type:bigint;not null;uniqueIndex:uniq_idx_tenant_user_group,priority:2;comment:'用户ID'"`
	GroupId  int64 `gorm:"type:bigint;not null;uniqueIndex:uniq_idx_tenant_user_group,priority:3;comment:'用户组ID'"`
	Ctime    int64 `gorm:"comment:'创建时间'"`
}

type IGroupDAO interface {
	Insert(ctx context.Context, g Group) (int64, error)
	Update(ctx context.Context, g Group) (int64, error)
	Delete(ctx context.Context, id int64) error
	GetByCode(ctx context.Context, code string) (Group, error)
	GetByID(ctx context.Context, id int64) (Group, error)
	List(ctx context.Context, offset, limit int64) ([]Group, int64, error)

	// 组-用户关系
	BindMembers(ctx context.Context, bindings []UserGroup) error
	UnbindMembers(ctx context.Context, groupID int64, userIDs []int64) error
	ListMembers(ctx context.Context, groupID int64, offset, limit int64, keyword string) ([]User, int64, error)
	CountMembers(ctx context.Context, groupID int64) (int64, error)
}

type groupDAO struct {
	db *gorm.DB
}

func NewGroupDAO(db *gorm.DB) IGroupDAO {
	return &groupDAO{db: db}
}

func (dao *groupDAO) Insert(ctx context.Context, g Group) (int64, error) {
	now := time.Now().UnixMilli()
	g.Ctime = now
	g.Utime = now
	err := dao.db.WithContext(ctx).Create(&g).Error
	return g.Id, err
}

func (dao *groupDAO) Update(ctx context.Context, g Group) (int64, error) {
	res := dao.db.WithContext(ctx).Model(&Group{}).
		Where("id = ?", g.Id).Updates(map[string]interface{}{
		"name":  g.Name,
		"desc":  g.Desc,
		"utime": time.Now().UnixMilli(),
	})
	return res.RowsAffected, res.Error
}

func (dao *groupDAO) Delete(ctx context.Context, id int64) error {
	return dao.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 删除用户组关系
		if err := tx.Where("group_id = ?", id).Delete(&UserGroup{}).Error; err != nil {
			return err
		}
		// 删除用户组本身
		return tx.Delete(&Group{}, id).Error
	})
}

func (dao *groupDAO) GetByCode(ctx context.Context, code string) (Group, error) {
	var g Group
	err := dao.db.WithContext(ctx).Where("code = ?", code).First(&g).Error
	return g, err
}

func (dao *groupDAO) GetByID(ctx context.Context, id int64) (Group, error) {
	var g Group
	err := dao.db.WithContext(ctx).Where("id = ?", id).First(&g).Error
	return g, err
}

func (dao *groupDAO) List(ctx context.Context, offset, limit int64) ([]Group, int64, error) {
	var (
		gs    []Group
		total int64
	)
	db := dao.db.WithContext(ctx).Model(&Group{})
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	err := db.Offset(int(offset)).Limit(int(limit)).Order("ctime DESC").Find(&gs).Error
	return gs, total, err
}

func (dao *groupDAO) BindMembers(ctx context.Context, bindings []UserGroup) error {
	if len(bindings) == 0 {
		return nil
	}
	now := time.Now().UnixMilli()
	for i := range bindings {
		bindings[i].Ctime = now
	}
	return dao.db.WithContext(ctx).Clauses(clause.OnConflict{
		DoNothing: true,
	}).Create(&bindings).Error
}

func (dao *groupDAO) UnbindMembers(ctx context.Context, groupID int64, userIDs []int64) error {
	if len(userIDs) == 0 {
		return nil
	}
	return dao.db.WithContext(ctx).Where("group_id = ? AND user_id IN ?", groupID, userIDs).Delete(&UserGroup{}).Error
}

func (dao *groupDAO) ListMembers(ctx context.Context, groupID int64, offset, limit int64, keyword string) ([]User, int64, error) {
	var (
		users []User
		total int64
	)

	subQuery := dao.db.WithContext(ctx).Model(&UserGroup{}).
		Where("group_id = ?", groupID).
		Select("user_id")

	db := dao.db.WithContext(ctx).Model(&User{}).Where("id IN (?)", subQuery)
	if keyword != "" {
		db = db.Where("username LIKE ?", "%"+keyword+"%")
	}

	err := db.Count(&total).Error
	if err != nil || total == 0 {
		return nil, 0, err
	}

	err = db.Offset(int(offset)).Limit(int(limit)).Order("ctime DESC").Find(&users).Error
	return users, total, err
}

func (dao *groupDAO) CountMembers(ctx context.Context, groupID int64) (int64, error) {
	var count int64
	err := dao.db.WithContext(ctx).Model(&UserGroup{}).Where("group_id = ?", groupID).Count(&count).Error
	return count, err
}

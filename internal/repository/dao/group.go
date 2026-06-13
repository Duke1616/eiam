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

// IGroupDAO 用户组数据访问对象接口
type IGroupDAO interface {
	// Insert 插入新用户组
	Insert(ctx context.Context, g Group) (int64, error)
	// Update 更新用户组基本信息
	Update(ctx context.Context, g Group) (int64, error)
	// Delete 删除用户组，并删除其下的所有成员关联
	Delete(ctx context.Context, id int64) error
	// GetByCode 根据唯一标识码查询用户组
	GetByCode(ctx context.Context, code string) (Group, error)
	// GetByID 根据ID查询用户组
	GetByID(ctx context.Context, id int64) (Group, error)
	// List 分页查询用户组列表
	List(ctx context.Context, offset, limit int64) ([]Group, int64, error)
	// Search 根据关键字分页模糊搜索用户组
	Search(ctx context.Context, offset, limit int64, keyword string) ([]Group, error)
	// CountSearch 模糊搜索用户组的总数
	CountSearch(ctx context.Context, keyword string) (int64, error)

	// BindMembers 批量绑定用户组成员关系
	BindMembers(ctx context.Context, bindings []UserGroup) error
	// UnbindMembers 批量解绑用户组成员关系
	UnbindMembers(ctx context.Context, groupID int64, userIDs []int64) error
	// ListMembers 分页查询该用户组下的成员列表，支持按关键字搜索
	ListMembers(ctx context.Context, groupID int64, offset, limit int64, keyword string) ([]User, int64, error)
	// CountMembers 获取该用户组下的成员数量
	CountMembers(ctx context.Context, groupID int64) (int64, error)
	// ListGroupsByUserID 分页查询用户所属的用户组列表，支持按关键字过滤
	ListGroupsByUserID(ctx context.Context, userID int64, offset, limit int64, keyword string) ([]Group, int64, error)
	// ListGroupsByCodes 根据组编码列表分页查询用户组，支持按关键字过滤
	ListGroupsByCodes(ctx context.Context, codes []string, offset, limit int64, keyword string) ([]Group, int64, error)
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

func (dao *groupDAO) Search(ctx context.Context, offset, limit int64, keyword string) ([]Group, error) {
	var gs []Group
	db := dao.db.WithContext(ctx).Model(&Group{})
	if keyword != "" {
		db = db.Where("name LIKE ? OR code LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}
	err := db.Offset(int(offset)).Limit(int(limit)).Order("ctime DESC").Find(&gs).Error
	return gs, err
}

func (dao *groupDAO) CountSearch(ctx context.Context, keyword string) (int64, error) {
	var total int64
	db := dao.db.WithContext(ctx).Model(&Group{})
	if keyword != "" {
		db = db.Where("name LIKE ? OR code LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}
	err := db.Count(&total).Error
	return total, err
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

func (dao *groupDAO) ListGroupsByUserID(ctx context.Context, userID int64, offset, limit int64, keyword string) ([]Group, int64, error) {
	var (
		gs    []Group
		total int64
	)

	subQuery := dao.db.WithContext(ctx).Model(&UserGroup{}).
		Where("user_id = ?", userID).
		Select("group_id")

	db := dao.db.WithContext(ctx).Model(&Group{}).
		Where("id IN (?)", subQuery)
	if keyword != "" {
		db = db.Where("name LIKE ? OR code LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}

	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	err := db.Offset(int(offset)).Limit(int(limit)).Order("ctime DESC").Find(&gs).Error
	return gs, total, err
}

func (dao *groupDAO) ListGroupsByCodes(ctx context.Context, codes []string, offset, limit int64, keyword string) ([]Group, int64, error) {
	var (
		gs    []Group
		total int64
	)

	db := dao.db.WithContext(ctx).Model(&Group{}).
		Where("code IN ?", codes)
	if keyword != "" {
		db = db.Where("name LIKE ? OR code LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}

	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	err := db.Offset(int(offset)).Limit(int(limit)).Order("ctime DESC").Find(&gs).Error
	return gs, total, err
}

package dao

import (
	"context"

	"github.com/Duke1616/eiam/pkg/sqlx"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// IUserDAO 用户数据持久化接口
type IUserDAO interface {
	// Create 新增基础用户记录
	Create(ctx context.Context, u User) (int64, error)
	// Update 事务性更新用户基础资料与名片信息
	Update(ctx context.Context, u User, ui UserProfile) (int64, error)

	// FindById 根据 ID 获取基础用户对象
	FindById(ctx context.Context, id int64) (User, error)
	// FindByUsername 根据用户名获取基础用户对象
	FindByUsername(ctx context.Context, username string) (User, error)

	// FindProfileByUserId 获取用户业务名片 (Profile)
	FindProfileByUserId(ctx context.Context, userID int64) (UserProfile, error)

	// FindProfilesByUserIds 批量获取用户业务名片
	FindProfilesByUserIds(ctx context.Context, userIDs []int64) ([]UserProfile, error)
	// FindIdentitiesByUserId 获取单个绑定的所有外部身份源信息
	FindIdentitiesByUserId(ctx context.Context, userID int64) ([]UserIdentity, error)
	// FindIdentitiesByUserIds 获取用户绑定的所有外部身份源信息
	FindIdentitiesByUserIds(ctx context.Context, userIDs []int64) ([]UserIdentity, error)
	// SaveProfile 保存或更新名片信息
	SaveProfile(ctx context.Context, ui UserProfile) error
	// SaveIdentity 绑定或更新外部身份源 (Ldap/Feishu 等)
	SaveIdentity(ctx context.Context, ui UserIdentity) error

	// FindIdentityByExternal 根据第三方平台的唯一标识查找关联身份
	FindIdentityByExternal(ctx context.Context, provider, externalID string) (UserIdentity, error)

	// List 分页查询基础用户列表
	List(ctx context.Context, offset, limit int64) ([]User, error)
	// ListByTenantMembership 分页查询当前租户成员用户列表
	ListByTenantMembership(ctx context.Context, offset, limit int64) ([]User, error)
	// Count 统计用户总数
	Count(ctx context.Context) (int64, error)
	// CountTenantMembers 统计当前租户成员总数
	CountTenantMembers(ctx context.Context) (int64, error)
	// Search 模糊搜索用户 (支持 username 或 nickname 维度)
	// 在多租户系统中，此查询只返回当前租户的成员
	Search(ctx context.Context, keyword string, offset, limit int64) ([]User, error)
	// CountByKeyword 统计搜索结果总数
	// 在多租户系统中，此统计只计算当前租户成员范围
	CountByKeyword(ctx context.Context, keyword string) (int64, error)
	// Delete 删除用户
	Delete(ctx context.Context, id int64) error
	// FindUsersByUsernames 批量根据用户名获取用户
	FindUsersByUsernames(ctx context.Context, usernames []string) ([]User, error)
	// BatchUpsertUsers 批量更新/写入基础用户资料
	BatchUpsertUsers(ctx context.Context, users []User) error
	// BatchUpsertProfilesAndIdentities 批量更新/写入名片与身份标记
	BatchUpsertProfilesAndIdentities(ctx context.Context, profiles []UserProfile, identities []UserIdentity) error
}

type userDAO struct {
	db *gorm.DB
}

func NewUserDAO(db *gorm.DB) IUserDAO {
	return &userDAO{db: db}
}

type User struct {
	ID       int64  `gorm:"primaryKey;autoIncrement"`
	Username string `gorm:"uniqueIndex;type:varchar(64)"`
	Password string `gorm:"type:varchar(255)"`
	Email    string `gorm:"type:varchar(128)"`
	Status   int    `gorm:"type:tinyint"`
	Ctime    int64  `gorm:"comment:'创建时间'"`
	Utime    int64  `gorm:"comment:'更新时间'"`
}

type UserProfile struct {
	ID       int64  `gorm:"primaryKey;autoIncrement"`
	UserID   int64  `gorm:"uniqueIndex"`
	Nickname string `gorm:"type:varchar(64)"`
	Avatar   string `gorm:"type:varchar(255)"`
	JobTitle string `gorm:"type:varchar(128)"`
}

type UserIdentity struct {
	ID       int64  `gorm:"primaryKey;autoIncrement"`
	UserID   int64  `gorm:"index"`
	Provider string `gorm:"index:idx_prov_key;type:varchar(32)"`

	LdapInfo   sqlx.JSONColumn[LdapInfo]   `gorm:"type:json" json:"ldap_info"`
	FeishuInfo sqlx.JSONColumn[FeishuInfo] `gorm:"type:json" json:"feishu_info"`
	WechatInfo sqlx.JSONColumn[WechatInfo] `gorm:"type:json" json:"wechat_info"`
}

type LdapInfo struct {
	DN string `json:"dn"`
}

type WechatInfo struct {
	UserID string `json:"user_id"`
}

type FeishuInfo struct {
	OpenID string `json:"open_id"`
	UserID string `json:"user_id"`
}

func (dao *userDAO) Create(ctx context.Context, u User) (int64, error) {
	err := dao.db.WithContext(ctx).Create(&u).Error
	return u.ID, err
}

func (dao *userDAO) Update(ctx context.Context, u User, ui UserProfile) (int64, error) {
	err := dao.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 1. 更新全球 User 基础资料
		if err := tx.Updates(&u).Error; err != nil {
			return err
		}

		// 2. 名片 Upsert：针对 UserId 冲突则更新昵称和职位
		// 确保在初次入职时，如果不存在记录则创建
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"nickname", "avatar", "job_title"}),
		}).Create(&ui).Error
	})
	return u.ID, err
}

func (dao *userDAO) FindById(ctx context.Context, id int64) (User, error) {
	var u User
	err := dao.db.WithContext(ctx).Where("id = ?", id).First(&u).Error
	return u, err
}

func (dao *userDAO) FindByUsername(ctx context.Context, username string) (User, error) {
	var u User
	err := dao.db.WithContext(ctx).Where("username = ?", username).First(&u).Error
	return u, err
}

func (dao *userDAO) FindProfileByUserId(ctx context.Context, userID int64) (UserProfile, error) {
	var ui UserProfile
	err := dao.db.WithContext(ctx).Where("user_id = ?", userID).First(&ui).Error
	return ui, err
}

func (dao *userDAO) FindProfilesByUserIds(ctx context.Context, userIDs []int64) ([]UserProfile, error) {
	var profiles []UserProfile
	if len(userIDs) == 0 {
		return profiles, nil
	}
	err := dao.db.WithContext(ctx).Where("user_id IN ?", userIDs).Find(&profiles).Error
	return profiles, err
}

func (dao *userDAO) SearchProfilesByNickname(ctx context.Context, keyword string) ([]UserProfile, error) {
	var profiles []UserProfile
	if keyword == "" {
		return profiles, nil
	}
	kw := "%" + keyword + "%"
	err := dao.db.WithContext(ctx).Where("nickname LIKE ?", kw).Find(&profiles).Error
	return profiles, err
}

func (dao *userDAO) SaveProfile(ctx context.Context, ui UserProfile) error {
	return dao.db.WithContext(ctx).Save(&ui).Error
}

func (dao *userDAO) SaveIdentity(ctx context.Context, ui UserIdentity) error {
	return dao.db.WithContext(ctx).Save(&ui).Error
}

func (dao *userDAO) FindIdentitiesByUserId(ctx context.Context, userID int64) ([]UserIdentity, error) {
	var identities []UserIdentity
	err := dao.db.WithContext(ctx).Where("user_id = ?", userID).Find(&identities).Error
	return identities, err
}

func (dao *userDAO) FindIdentitiesByUserIds(ctx context.Context, userIDs []int64) ([]UserIdentity, error) {
	var identities []UserIdentity
	err := dao.db.WithContext(ctx).Where("user_id IN ?", userIDs).Find(&identities).Error
	return identities, err
}

func (dao *userDAO) FindIdentityByExternal(ctx context.Context, provider, externalID string) (UserIdentity, error) {
	var y UserIdentity
	query := dao.db.WithContext(ctx).Where("provider = ?", provider)

	switch provider {
	case "ldap":
		query = query.Where("ldap_info ->> '$.dn' = ?", externalID)
	case "feishu":
		query = query.Where("feishu_info ->> '$.user_id' = ?", externalID)
	case "wechat":
		query = query.Where("wechat_info ->> '$.user_id' = ?", externalID)
	default:
		return y, gorm.ErrRecordNotFound
	}

	err := query.First(&y).Error
	return y, err
}

func (dao *userDAO) List(ctx context.Context, offset, limit int64) ([]User, error) {
	var us []User
	err := dao.db.WithContext(ctx).Offset(int(offset)).Limit(int(limit)).Find(&us).Error
	return us, err
}

func (dao *userDAO) Count(ctx context.Context) (int64, error) {
	var total int64
	err := dao.db.WithContext(ctx).Model(&User{}).Count(&total).Error
	return total, err
}

func (dao *userDAO) CountByKeyword(ctx context.Context, keyword string) (int64, error) {
	var total int64
	db := dao.db.WithContext(ctx).Model(&User{})
	if keyword != "" {
		kw := "%" + keyword + "%"
		db = db.Where("username LIKE ?", kw)
	}

	subQuery := dao.db.WithContext(ctx).Model(&Membership{}).Select("user_id")
	err := db.Where("id IN (?)", subQuery).Count(&total).Error
	return total, err
}

func (dao *userDAO) CountTenantMembers(ctx context.Context) (int64, error) {
	var total int64
	subQuery := dao.db.WithContext(ctx).Model(&Membership{}).Select("user_id")
	err := dao.db.WithContext(ctx).Model(&User{}).Where("id IN (?)", subQuery).Count(&total).Error
	return total, err
}

func (dao *userDAO) Search(ctx context.Context, keyword string, offset, limit int64) ([]User, error) {
	var us []User
	db := dao.db.WithContext(ctx).Model(&User{})
	if keyword != "" {
		kw := "%" + keyword + "%"
		db = db.Where("username LIKE ?", kw)
	}
	subQuery := dao.db.WithContext(ctx).Model(&Membership{}).Select("user_id")
	err := db.Where("id IN (?)", subQuery).Offset(int(offset)).Limit(int(limit)).Find(&us).Error
	return us, err
}

func (dao *userDAO) ListByTenantMembership(ctx context.Context, offset, limit int64) ([]User, error) {
	var us []User
	subQuery := dao.db.WithContext(ctx).Model(&Membership{}).Select("user_id")
	err := dao.db.WithContext(ctx).Model(&User{}).Where("id IN (?)", subQuery).Offset(int(offset)).Limit(int(limit)).Find(&us).Error
	return us, err
}

func (dao *userDAO) Delete(ctx context.Context, id int64) error {
	return dao.db.WithContext(ctx).Delete(&User{}, id).Error
}

func (dao *userDAO) FindUsersByUsernames(ctx context.Context, usernames []string) ([]User, error) {
	var users []User
	if len(usernames) == 0 {
		return users, nil
	}
	err := dao.db.WithContext(ctx).Where("username IN ?", usernames).Find(&users).Error
	return users, err
}

func (dao *userDAO) BatchUpsertUsers(ctx context.Context, users []User) error {
	if len(users) == 0 {
		return nil
	}
	return dao.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "username"}},
		DoUpdates: clause.AssignmentColumns([]string{"email", "status", "utime"}),
	}).Create(&users).Error
}

func (dao *userDAO) BatchUpsertProfilesAndIdentities(ctx context.Context, profiles []UserProfile, identities []UserIdentity) error {
	return dao.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if len(profiles) > 0 {
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "user_id"}},
				DoUpdates: clause.AssignmentColumns([]string{"nickname", "avatar", "job_title"}),
			}).Create(&profiles).Error; err != nil {
				return err
			}
		}

		if len(identities) > 0 {
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "provider"}, {Name: "user_id"}},
				DoUpdates: clause.AssignmentColumns([]string{"ldap_info", "feishu_info", "wechat_info"}),
			}).Create(&identities).Error; err != nil {
				return err
			}
		}

		return nil
	})
}

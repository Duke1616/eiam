package dao

import (
	"context"

	"github.com/Duke1616/eiam/pkg/sqlx"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// IUserDAO 用户数据持久化接口
type IUserDAO interface {
	Create(ctx context.Context, u User) (int64, error)
	Update(ctx context.Context, u User, ui UserProfile) (int64, error)
	
	FindById(ctx context.Context, id int64) (User, error)
	FindByUsername(ctx context.Context, username string) (User, error)
	
	FindProfileByMembershipId(ctx context.Context, membershipID int64) (UserProfile, error)
	FindIdentitiesByUserId(ctx context.Context, userID int64) ([]UserIdentity, error)
	
	SaveProfile(ctx context.Context, ui UserProfile) error
	SaveIdentity(ctx context.Context, ui UserIdentity) error
	
	FindIdentityByExternal(ctx context.Context, provider, externalID string) (UserIdentity, error)

	List(ctx context.Context, offset, limit int64) ([]User, error)
	Count(ctx context.Context) (int64, error)
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
	ID           int64  `gorm:"primaryKey;autoIncrement"`
	MembershipID int64  `gorm:"uniqueIndex"` 
	Nickname     string `gorm:"type:varchar(64)"`
	Avatar       string `gorm:"type:varchar(255)"`
	JobTitle     string `gorm:"type:varchar(128)"`
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
		
		// 2. 名片 Upsert：针对 MembershipId 冲突则更新昵称和职位
		// 确保在初次入职时，如果不存在记录则创建
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "membership_id"}},
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

func (dao *userDAO) FindProfileByMembershipId(ctx context.Context, membershipID int64) (UserProfile, error) {
	var ui UserProfile
	err := dao.db.WithContext(ctx).Where("membership_id = ?", membershipID).First(&ui).Error
	return ui, err
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

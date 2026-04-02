package dao

import (
	"context"

	"github.com/Duke1616/eiam/pkg/sqlx"
	"gorm.io/gorm"
)

// IUserDAO 用户数据持久化接口：完全剥离 JOIN，仅执行高性能单表操作
type IUserDAO interface {
	// Create 创建用户账号及关联的详细资料 (事务操作)
	Create(ctx context.Context, u User, ui UserInfo) (int64, error)
	// Update 更新用户账号及关联的详细资料 (事务操作)
	Update(ctx context.Context, u User, ui UserInfo) (int64, error)
	
	// FindById 单表根据主键 ID 获取账号信息
	FindById(ctx context.Context, id int64) (User, error)
	// FindByUsername 单表根据用户名获取账号信息
	FindByUsername(ctx context.Context, username string) (User, error)
	// FindInfoByUserId 单表根据 UserID 获取用户详情资料
	FindInfoByUserId(ctx context.Context, userId int64) (UserInfo, error)
	
	// List 分页获取账号列表
	List(ctx context.Context, offset, limit int64) ([]User, error)
	// Count 获取租户下总账号数量
	Count(ctx context.Context) (int64, error)

	// SaveIdentity 保存联邦身份映射 (LDAP DN, Feishu ID 等)
	SaveIdentity(ctx context.Context, ui UserIdentity) error
	// FindIdentityByUserId 获取用户特定的身份源绑定
	FindIdentityByUserId(ctx context.Context, userId int64, provider string) (UserIdentity, error)
	// FindIdentitiesByUserId 获取该用户所有的联邦身份绑定
	FindIdentitiesByUserId(ctx context.Context, userId int64) ([]UserIdentity, error)
	// FindIdentityByExternal 通过外部唯一标识（如 DN）查找身份映射
	FindIdentityByExternal(ctx context.Context, provider, externalID string) (UserIdentity, error)
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
	TenantID int64  `gorm:"index"`
	Ctime    int64  `gorm:"comment:'创建时间';autoCreateTime"`
	Utime    int64  `gorm:"comment:'更新时间';autoUpdateTime"`
}

type UserInfo struct {
	ID       int64                              `gorm:"primaryKey;autoIncrement"`
	UserID   int64                              `gorm:"uniqueIndex"`
	Nickname string                             `gorm:"type:varchar(64)"`
	Avatar   string                             `gorm:"type:varchar(255)"`
	JobTitle string                             `gorm:"type:varchar(128)"`
	Metadata sqlx.JSONColumn[map[string]string] `gorm:"type:json"`
}

type UserIdentity struct {
	ID         int64                              `gorm:"primaryKey;autoIncrement"`
	UserID     int64                              `gorm:"index:idx_user_provider"`
	Provider   string                             `gorm:"index:idx_user_provider;type:varchar(32)"`
	ExternalID string                             `gorm:"index:idx_provider_external;type:varchar(255)"`
	Extra      sqlx.JSONColumn[map[string]string] `gorm:"type:json"`
}

func (dao *userDAO) Create(ctx context.Context, u User, ui UserInfo) (int64, error) {
	err := dao.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&u).Error; err != nil {
			return err
		}
		ui.UserID = u.ID
		return tx.Create(&ui).Error
	})
	return u.ID, err
}

func (dao *userDAO) Update(ctx context.Context, u User, ui UserInfo) (int64, error) {
	err := dao.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Updates(&u).Error; err != nil {
			return err
		}
		return tx.Where("user_id = ?", u.ID).Updates(&ui).Error
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

func (dao *userDAO) FindInfoByUserId(ctx context.Context, userId int64) (UserInfo, error) {
	var ui UserInfo
	err := dao.db.WithContext(ctx).Where("user_id = ?", userId).First(&ui).Error
	return ui, err
}

func (dao *userDAO) SaveIdentity(ctx context.Context, ui UserIdentity) error {
	return dao.db.WithContext(ctx).Save(&ui).Error
}

func (dao *userDAO) FindIdentityByUserId(ctx context.Context, userId int64, provider string) (UserIdentity, error) {
	var ui UserIdentity
	err := dao.db.WithContext(ctx).Where("user_id = ? AND provider = ?", userId, provider).First(&ui).Error
	return ui, err
}

func (dao *userDAO) FindIdentitiesByUserId(ctx context.Context, userId int64) ([]UserIdentity, error) {
	var identities []UserIdentity
	err := dao.db.WithContext(ctx).Where("user_id = ?", userId).Find(&identities).Error
	return identities, err
}

func (dao *userDAO) FindIdentityByExternal(ctx context.Context, provider, externalID string) (UserIdentity, error) {
	var y UserIdentity
	err := dao.db.WithContext(ctx).Where("provider = ? AND external_id = ?", provider, externalID).First(&y).Error
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

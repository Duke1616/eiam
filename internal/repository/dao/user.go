package dao

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/ctxutil"
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
	// FindByIds 批量根据 ID 获取基础用户对象
	FindByIds(ctx context.Context, ids []int64) ([]User, error)
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

	// List 分页模糊查询用户列表（支持 tid 隔离与关键字搜索）
	List(ctx context.Context, offset, limit int64, keyword string) ([]User, error)
	// Count 统计用户总数
	Count(ctx context.Context, keyword string) (int64, error)
	// Search 模糊搜索当前租户下的成员用户
	Search(ctx context.Context, keyword string, offset, limit int64) ([]User, error)
	// CountSearch 统计搜索结果总数
	CountSearch(ctx context.Context, keyword string) (int64, error)
	// Delete 删除用户
	Delete(ctx context.Context, id int64) error
	// FindUsersByUsernames 批量根据用户名获取用户
	FindUsersByUsernames(ctx context.Context, usernames []string) ([]User, error)
	// GetAttachedUsersWithFilter 联表分页获取关联角色的用户详情，支持关键词过滤
	GetAttachedUsersWithFilter(ctx context.Context, roleCode string, offset, limit int64, keyword string) ([]User, int64, error)
	// BatchUpsertUsers 批量更新/写入基础用户资料
	BatchUpsertUsers(ctx context.Context, users []User) error
	// BatchUpsertProfilesAndIdentities 批量更新/写入名片与身份标记
	BatchUpsertProfilesAndIdentities(ctx context.Context, profiles []UserProfile, identities []UserIdentity) error
	// UpdateLastLoginAt 更新最近登录时间
	UpdateLastLoginAt(ctx context.Context, id int64, loginAt int64) error
	// DeleteIdentity 解除外部身份绑定
	DeleteIdentity(ctx context.Context, userID int64, provider string) error
}

type userDAO struct {
	db *gorm.DB
}

func NewUserDAO(db *gorm.DB) IUserDAO {
	return &userDAO{db: db}
}

// membershipScope 封装多租户 Membership 隔离逻辑
// 返回一个 GORM Scope 函数，自动注入针对指定租户的成员过滤条件
func (dao *userDAO) membershipScope(tid int64) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		subQuery := dao.db.Session(&gorm.Session{}).Model(&Membership{}).
			Where("tenant_id = ?", tid).
			Select("user_id")
		return db.Where("id IN (?)", subQuery)
	}
}

type User struct {
	ID          int64  `gorm:"primaryKey;autoIncrement"`
	Username    string `gorm:"column:username;uniqueIndex;type:varchar(64)"`
	Password    string `gorm:"type:varchar(255)"`
	Email       string `gorm:"type:varchar(128)"`
	Status      int    `gorm:"type:tinyint"`
	Source      string `gorm:"type:varchar(32);index;comment:'身份来源: local, ldap等'"`
	Ctime       int64  `gorm:"comment:'创建时间'"`
	Utime       int64  `gorm:"comment:'更新时间'"`
	LastLoginAt int64  `gorm:"comment:'最近登录时间'"`
}

type UserProfile struct {
	ID       int64  `gorm:"primaryKey;autoIncrement"`
	UserID   int64  `gorm:"uniqueIndex"`
	Nickname string `gorm:"type:varchar(64)"`
	Avatar   string `gorm:"type:varchar(255)"`
	JobTitle string `gorm:"type:varchar(128)"`
	Phone    string `gorm:"type:varchar(32)"`
}

type UserIdentity struct {
	ID       int64  `gorm:"primaryKey;autoIncrement"`
	UserID   int64  `gorm:"uniqueIndex:idx_user_provider"`
	Provider string `gorm:"uniqueIndex:idx_user_provider;type:varchar(32)"`

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
	now := time.Now().UnixMilli()
	u.Ctime = now
	u.Utime = now
	err := dao.db.WithContext(ctx).Create(&u).Error
	return u.ID, err
}

func (dao *userDAO) Update(ctx context.Context, u User, ui UserProfile) (int64, error) {
	err := dao.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now().UnixMilli()
		u.Utime = now
		// 1. 更新全球 User 基础资料
		if err := tx.Model(&u).Updates(&u).Error; err != nil {
			return err
		}

		// 2. 名片 Upsert：针对 UserId 冲突则更新昵称和职位
		// 确保在初次入职时，如果不存在记录则创建
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"nickname", "avatar", "job_title", "phone"}),
		}).Create(&ui).Error
	})
	return u.ID, err
}

func (dao *userDAO) FindById(ctx context.Context, id int64) (User, error) {
	var u User
	err := dao.db.WithContext(ctx).Where("id = ?", id).First(&u).Error
	return u, err
}

func (dao *userDAO) FindByIds(ctx context.Context, ids []int64) ([]User, error) {
	var users []User
	if len(ids) == 0 {
		return users, nil
	}
	err := dao.db.WithContext(ctx).Where("id IN ?", ids).Find(&users).Error
	return users, err
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
	return dao.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "provider"}},
		DoUpdates: clause.AssignmentColumns([]string{"ldap_info", "feishu_info", "wechat_info"}),
	}).Create(&ui).Error
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

func (dao *userDAO) List(ctx context.Context, offset, limit int64, keyword string) ([]User, error) {
	var us []User
	tid := ctxutil.GetTenantID(ctx).Int64()
	db := dao.db.WithContext(ctx).Model(&User{})

	// 核心逻辑：只有在系统租户 (ID=1) 且非成员搜索场景下，才允许看到全量“国籍”用户
	if tid != ctxutil.SystemTenantID {
		db = db.Scopes(dao.membershipScope(tid))
	}

	if keyword != "" {
		db = db.Where("username LIKE ?", "%"+keyword+"%")
	}

	err := db.Offset(int(offset)).Limit(int(limit)).Order("ctime DESC").Find(&us).Error
	return us, err
}

func (dao *userDAO) Count(ctx context.Context, keyword string) (int64, error) {
	var total int64
	tid := ctxutil.GetTenantID(ctx).Int64()
	db := dao.db.WithContext(ctx).Model(&User{})

	if tid != ctxutil.SystemTenantID {
		db = db.Scopes(dao.membershipScope(tid))
	}

	if keyword != "" {
		db = db.Where("username LIKE ?", "%"+keyword+"%")
	}

	err := db.Count(&total).Error
	return total, err
}

func (dao *userDAO) Search(ctx context.Context, keyword string, offset, limit int64) ([]User, error) {
	var us []User
	tid := ctxutil.GetTenantID(ctx).Int64()
	// NOTE: Search 明确用于成员授权/搜索场景，即便是系统租户也必须强制过滤，避免数据泄露
	db := dao.db.WithContext(ctx).Model(&User{}).Scopes(dao.membershipScope(tid))

	if keyword != "" {
		db = db.Where("username LIKE ?", "%"+keyword+"%")
	}

	// 增加排序，使其能替代原有的 ListMembers
	err := db.Offset(int(offset)).Limit(int(limit)).Order("ctime DESC").Find(&us).Error
	return us, err
}

func (dao *userDAO) CountSearch(ctx context.Context, keyword string) (int64, error) {
	var total int64
	tid := ctxutil.GetTenantID(ctx).Int64()
	db := dao.db.WithContext(ctx).Model(&User{}).Scopes(dao.membershipScope(tid))

	if keyword != "" {
		db = db.Where("username LIKE ?", "%"+keyword+"%")
	}

	err := db.Count(&total).Error
	return total, err
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

func (dao *userDAO) GetAttachedUsersWithFilter(ctx context.Context, roleCode string, offset, limit int64, keyword string) ([]User, int64, error) {
	var (
		us    []User
		total int64
	)

	tid := ctxutil.GetTenantID(ctx).Int64()

	// 1. 构造内部关联子查询：从 casbin_rule 中获取该角色关联该用户的时间 (存放在 v3)
	subQueryExpr := dao.db.Table("casbin_rule").
		Select("CAST(v3 AS SIGNED)").
		Where("REPLACE(casbin_rule.v0, ?, '') = user.username", domain.PrefixUser).
		Where("ptype = 'g' AND v1 = ? AND v2 = ?", domain.RoleSubject(roleCode), tid)

	// 2. 构造过滤子查询：找出该租户下关联该角色的所有用户标识 (v0)
	filterSubQuery := dao.db.Table("casbin_rule").
		Select("REPLACE(v0, ?, '')", domain.PrefixUser).
		Where("ptype = 'g' AND v1 = ? AND v2 = ?", domain.RoleSubject(roleCode), tid)

	// 3. 主查询：注入关联时间并过滤
	query := dao.db.WithContext(ctx).Model(&User{}).
		Select("*, (?) AS ctime", subQueryExpr).
		Where("username IN (?)", filterSubQuery)

	if keyword != "" {
		kw := "%" + keyword + "%"
		query = query.Where("username LIKE ?", kw)
	}

	err := query.Count(&total).Error
	if err != nil || total == 0 {
		return nil, 0, err
	}

	// 按照授权时间 (ctime) 倒序排列
	err = query.Offset(int(offset)).Limit(int(limit)).
		Order("ctime DESC").Find(&us).Error

	return us, total, err
}

func (dao *userDAO) BatchUpsertUsers(ctx context.Context, users []User) error {
	if len(users) == 0 {
		return nil
	}
	now := time.Now().UnixMilli()
	for i := range users {
		if users[i].Ctime == 0 {
			users[i].Ctime = now
		}
		users[i].Utime = now
	}
	return dao.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "username"}},
		DoUpdates: clause.AssignmentColumns([]string{"email", "status", "source", "utime"}),
	}).Create(&users).Error
}

func (dao *userDAO) BatchUpsertProfilesAndIdentities(ctx context.Context, profiles []UserProfile, identities []UserIdentity) error {
	return dao.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if len(profiles) > 0 {
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "user_id"}},
				DoUpdates: clause.AssignmentColumns([]string{"nickname", "avatar", "job_title", "phone"}),
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
func (dao *userDAO) UpdateLastLoginAt(ctx context.Context, id int64, loginAt int64) error {
	return dao.db.WithContext(ctx).Model(&User{}).Where("id = ?", id).Update("last_login_at", loginAt).Error
}

func (dao *userDAO) DeleteIdentity(ctx context.Context, userID int64, provider string) error {
	return dao.db.WithContext(ctx).
		Where("user_id = ? AND provider = ?", userID, provider).
		Delete(&UserIdentity{}).Error
}

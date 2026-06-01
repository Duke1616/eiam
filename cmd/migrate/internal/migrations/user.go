package migrations

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/Duke1616/ecmdb/pkg/cryptox"
	"github.com/Duke1616/eiam/cmd/migrate/internal/migration"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// ==================== 常量 ====================

const (
	collectionName             = "c_user"
	adminUsername              = "admin"
	defaultAdminPlainPwd       = "12345678" // 迁移用户统一初始密码，登录后强制重置
	systemTenantID       int64 = 1          // 系统根管理空间
	defaultTenantID      int64 = 2          // 默认租户空间
)

// ==================== MongoDB 源数据模型 ====================

type mongoUser struct {
	Id           int64           `bson:"id"`
	DepartmentId int64           `bson:"department_id"`
	Username     string          `bson:"username"`
	Password     string          `bson:"password"`
	Email        string          `bson:"email"`
	Title        string          `bson:"title"`
	DisplayName  string          `bson:"display_name"`
	CreateType   uint8           `bson:"create_type"`
	Status       uint8           `bson:"status"`
	Ctime        int64           `bson:"ctime"`
	Utime        int64           `bson:"utime"`
	RoleCodes    []string        `bson:"role_codes"`
	FeishuInfo   mongoFeishuInfo `bson:"feishu_info"`
	WechatInfo   mongoWechatInfo `bson:"wechat_info"`
}

type mongoFeishuInfo struct {
	UserId string `bson:"user_id"`
}

type mongoWechatInfo struct {
	UserId string `bson:"user_id"`
}

// ==================== User 基础表 (1:1) ====================

type userMigrator struct {
	crypto *cryptox.CryptoManager
}

func NewUserMigrator(encryptionKey, encryptionVersion string) migration.Migrator {
	var cm *cryptox.CryptoManager
	if encryptionKey != "" {
		cm = cryptox.NewCryptoManager("V2").
			Register("V2", cryptox.MustNewAESCryptoV2(encryptionKey)).
			Register(encryptionVersion, cryptox.MustNewAESCrypto(encryptionKey)).
			WithLegacyAlgo(encryptionVersion)
	}
	return migration.NewMongoMigrator[mongoUser, dao.User](userMigrator{crypto: cm})
}

func (userMigrator) Name() string           { return "user" }
func (userMigrator) CollectionName() string { return collectionName }
func (m userMigrator) Convert(src mongoUser) dao.User {
	return dao.User{
		ID:       src.Id,
		Username: src.Username,
		Email:    src.Email,
		Status:   int(src.Status),
		Password: m.migratePassword(src.Username, src.Password),
		Ctime:    src.Ctime,
		Utime:    src.Utime,
	}
}

// migratePassword 将 ecmdb 的 AES 加密密码解密后重新 bcrypt hash，
// 解密失败时降级为初始密码（登录后强制重置）。
func (m userMigrator) migratePassword(username, encrypted string) string {
	plain := ""
	if m.crypto != nil && encrypted != "" {
		decrypted, err := m.crypto.Decrypt(encrypted)
		if err != nil {
			log.Printf("[user] 解密 %s 密码失败: %v，降级为初始密码", username, err)
		} else {
			plain = decrypted
		}
	}
	if plain == "" {
		plain = defaultAdminPlainPwd
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		panic(fmt.Sprintf("bcrypt hash 计算失败: %v", err))
	}
	return string(hash)
}

// ==================== UserProfile 名片表 (1:1) ====================

type userProfileMigrator struct{}

func NewUserProfileMigrator() migration.Migrator {
	return migration.NewMongoMigrator[mongoUser, dao.UserProfile](userProfileMigrator{})
}

func (userProfileMigrator) Name() string           { return "user_profile" }
func (userProfileMigrator) CollectionName() string { return collectionName }
func (userProfileMigrator) Convert(src mongoUser) dao.UserProfile {
	return dao.UserProfile{
		UserID:   src.Id,
		Nickname: src.DisplayName,
		JobTitle: src.Title,
	}
}

// ==================== UserIdentity 身份表 (1:N) ====================

type userIdentityMigrator struct{}

func NewUserIdentityMigrator() migration.Migrator {
	return migration.NewMongoMigratorMany[mongoUser, dao.UserIdentity](userIdentityMigrator{})
}

func (userIdentityMigrator) Name() string           { return "user_identity" }
func (userIdentityMigrator) CollectionName() string { return collectionName }
func (userIdentityMigrator) ConvertMany(src mongoUser) []dao.UserIdentity {
	var out []dao.UserIdentity
	if src.FeishuInfo.UserId != "" {
		out = append(out, dao.UserIdentity{
			UserID:     src.Id,
			Provider:   "feishu",
			IdentityID: src.FeishuInfo.UserId,
			FeishuInfo: sqlx.JSONColumn[dao.FeishuInfo]{Val: dao.FeishuInfo{UserID: src.FeishuInfo.UserId}, Valid: true},
		})
	}
	if src.WechatInfo.UserId != "" {
		out = append(out, dao.UserIdentity{
			UserID:     src.Id,
			Provider:   "wechat",
			IdentityID: src.WechatInfo.UserId,
			WechatInfo: sqlx.JSONColumn[dao.WechatInfo]{Val: dao.WechatInfo{UserID: src.WechatInfo.UserId}, Valid: true},
		})
	}
	return out
}

// ==================== Membership 租户成员 (1:1) ====================
// 每个迁移用户自动入驻默认租户空间，否则无法登录使用。

type userMembershipMigrator struct{}

func NewUserMembershipMigrator() migration.Migrator {
	return migration.NewMongoMigrator[mongoUser, dao.Membership](userMembershipMigrator{})
}

func (userMembershipMigrator) Name() string           { return "user_membership" }
func (userMembershipMigrator) CollectionName() string { return collectionName }
func (userMembershipMigrator) Convert(src mongoUser) dao.Membership {
	return dao.Membership{
		TenantID: defaultTenantID,
		UserID:   src.Id,
		Ctime:    src.Ctime,
	}
}

// ==================== Pre/Post Hooks: admin 冲突处理 ====================

// NewUserPreMigrateHook 迁移前钩子：检测 MySQL ID=1 是否被 seed admin 占据，
// 若占据则清场（删除 seed admin 及其关联数据），腾出 ID=1。
// 直接查 MySQL 而非 MongoDB，规避 BSON int32/int64 类型不匹配导致查不到的问题。
func NewUserPreMigrateHook() migration.Hook {
	return func(ctx context.Context, env migration.MigrationEnv) error {
		if env.DryRun {
			return nil
		}

		// 直接查询 MySQL：ID=1 是否被 seed admin 占据
		var user dao.User
		err := env.MySQLDst.Where("id = ?", 1).First(&user).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				log.Println("[pre-check] MySQL ID=1 不存在，无冲突")
				return nil
			}
			return fmt.Errorf("查询 MySQL ID=1 失败: %w", err)
		}
		if user.Username != adminUsername {
			// ID=1 已被其他用户占据（前次迁入），跳过
			log.Printf("[pre-check] MySQL ID=1 已被 %q 占据（已迁入），跳过", user.Username)
			return nil
		}

		// ID=1 是 seed admin → 清场腾位
		log.Println("[pre-check] MySQL ID=1 是 seed admin，清理关联数据")
		if err = cascadeDeleteUser(env.MySQLDst, 1); err != nil {
			return err
		}
		log.Println("[pre-check] seed admin 及关联数据已清理，ID=1 已腾空")
		return nil
	}
}

// NewUserPostMigrateHook 迁移后钩子：
//  1. 确保 admin 用户存在 + 成员关系 + 权限规则完整
//  2. 为所有用户初始化个人租户空间（Tenant + Membership + CasbinRule）
func NewUserPostMigrateHook() migration.Hook {
	return func(ctx context.Context, env migration.MigrationEnv) error {
		if env.DryRun {
			return nil
		}

		// 1. 确保 admin 存在且关联数据完整
		var admin dao.User
		err := env.MySQLDst.Where("username = ?", adminUsername).First(&admin).Error
		if err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("查询 admin 失败: %w", err)
			}
			log.Println("[post-check] admin 不存在，开始补建")
			if err = rebuildAdmin(env.MySQLDst); err != nil {
				return err
			}
			log.Println("[post-check] admin 补建完成")
		} else {
			log.Printf("[post-check] admin 已存在 (ID=%d)，检查成员关系", admin.ID)
			if err = ensureAdminMemberships(env.MySQLDst, admin.ID); err != nil {
				return err
			}
		}

		// 2. 为所有用户初始化个人租户空间
		return initPersonalTenants(env.MySQLDst)
	}
}

// ==================== 内部辅助函数 ====================

// cascadeDeleteUser 级联删除指定用户的所有关联数据
// （CasbinRule → Profile → Identity → Membership → User）。
func cascadeDeleteUser(db *gorm.DB, userID int64) error {
	// 1. 清理 CasbinRule：按 username 关联的授权规则
	var user dao.User
	if err := db.Where("id = ?", userID).First(&user).Error; err == nil {
		if err = db.Where("ptype = 'g' AND v0 = ?", "user:"+user.Username).Delete(&dao.CasbinRule{}).Error; err != nil {
			return fmt.Errorf("清理 CasbinRule 失败: %w", err)
		}
	}

	// 2. 清理关联表
	for _, target := range []any{&dao.UserProfile{}, &dao.UserIdentity{}, &dao.Membership{}} {
		if err := db.Where("user_id = ?", userID).Delete(target).Error; err != nil {
			return fmt.Errorf("清理 %T 关联数据失败: %w", target, err)
		}
	}

	// 3. 删除用户行
	if err := db.Where("id = ?", userID).Delete(&dao.User{}).Error; err != nil {
		return fmt.Errorf("清理 user 失败: %w", err)
	}
	return nil
}

// rebuildAdmin 补建 admin 用户及其全部关联数据（名片 + 双租户成员关系 + 权限规则）。
func rebuildAdmin(db *gorm.DB) error {
	now := time.Now().UnixMilli()
	pwdHash, err := bcrypt.GenerateFromPassword([]byte(defaultAdminPlainPwd), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt hash 计算失败: %w", err)
	}
	admin := dao.User{
		Username: adminUsername,
		Password: string(pwdHash),
		Email:    "admin@example.com",
		Status:   1,
		Source:   "local",
		Ctime:    now,
		Utime:    now,
	}

	return db.Transaction(func(tx *gorm.DB) error {
		if err = tx.Create(&admin).Error; err != nil {
			return fmt.Errorf("补建 admin 用户失败: %w", err)
		}

		for _, record := range []any{
			&dao.UserProfile{UserID: admin.ID, Nickname: "系统管理员", JobTitle: "平台负责人"},
			&dao.Membership{TenantID: systemTenantID, UserID: admin.ID, Ctime: now},
			&dao.Membership{TenantID: defaultTenantID, UserID: admin.ID, Ctime: now},
		} {
			if err = tx.Create(record).Error; err != nil {
				return fmt.Errorf("补建 admin 关联数据失败: %w", err)
			}
		}

		// 补建 admin 权限规则
		for _, rule := range adminCasbinRules(now) {
			if err = tx.Create(&rule).Error; err != nil {
				return fmt.Errorf("补建 admin 权限规则失败: %w", err)
			}
		}
		return nil
	})
}

// ensureAdminMemberships 确保 admin 用户拥有系统租户和默认租户的成员关系及权限规则。
// Pre-hook 清场后迁移重插入 admin 时，成员关系和 CasbinRule 可能缺失，此函数补齐。
func ensureAdminMemberships(db *gorm.DB, adminID int64) error {
	now := time.Now().UnixMilli()

	// 1. 补齐缺失的成员关系
	for _, tid := range []int64{systemTenantID, defaultTenantID} {
		var count int64
		db.Model(&dao.Membership{}).Where("tenant_id = ? AND user_id = ?", tid, adminID).Count(&count)
		if count == 0 {
			if err := db.Create(&dao.Membership{TenantID: tid, UserID: adminID, Ctime: now}).Error; err != nil {
				return fmt.Errorf("补建 admin 成员关系(tenant=%d)失败: %w", tid, err)
			}
		}
	}

	// 2. 补齐缺失的权限规则
	for _, rule := range adminCasbinRules(now) {
		var count int64
		db.Model(&dao.CasbinRule{}).Where("ptype = ? AND v0 = ? AND v1 = ? AND v2 = ?",
			rule.Ptype, rule.V0, rule.V1, rule.V2).Count(&count)
		if count == 0 {
			if err := db.Create(&rule).Error; err != nil {
				return fmt.Errorf("补建 admin 权限规则失败: %w", err)
			}
		}
	}
	return nil
}

// adminCasbinRules 返回 admin 用户的标准权限规则。
func adminCasbinRules(now int64) []dao.CasbinRule {
	ts := strconv.FormatInt(now, 10)
	return []dao.CasbinRule{
		{Ptype: "g", V0: "user:admin", V1: "role:super_admin", V2: strconv.FormatInt(systemTenantID, 10), V3: ts},
		{Ptype: "g", V0: "user:admin", V1: "role:admin", V2: strconv.FormatInt(defaultTenantID, 10), V3: ts},
	}
}

// initPersonalTenants 为所有尚无个人空间的用户初始化个人租户空间。
// 每个用户获得：个人租户 + 成员关系 + admin 角色授权，与 JIT/LDAP 同步流程对齐。
func initPersonalTenants(db *gorm.DB) error {
	// 1. 查询所有用户
	var users []dao.User
	if err := db.Find(&users).Error; err != nil {
		return fmt.Errorf("查询用户列表失败: %w", err)
	}
	if len(users) == 0 {
		return nil
	}

	// 2. 批量查询已有个人空间的 code，构建去重集合
	var existingCodes []string
	if err := db.Model(&dao.Tenant{}).
		Where("code LIKE ?", "%-personal").
		Pluck("code", &existingCodes).Error; err != nil {
		return fmt.Errorf("查询已有个人空间失败: %w", err)
	}
	hasPersonal := make(map[string]struct{}, len(existingCodes))
	for _, c := range existingCodes {
		hasPersonal[c] = struct{}{}
	}

	// 3. 筛选需要创建个人空间的用户（admin 排除，其拥有系统管理空间无需个人空间）
	type pending struct {
		userID   int64
		username string
		code     string
	}
	var pendings []pending
	for _, u := range users {
		if u.Username == adminUsername {
			continue
		}
		code := u.Username + "-personal"
		if _, ok := hasPersonal[code]; !ok {
			pendings = append(pendings, pending{userID: u.ID, username: u.Username, code: code})
		}
	}
	if len(pendings) == 0 {
		log.Println("[post-check] 所有用户已有个人租户空间")
		return nil
	}

	log.Printf("[post-check] 需初始化 %d 个个人租户空间", len(pendings))
	now := time.Now().UnixMilli()

	return db.Transaction(func(tx *gorm.DB) error {
		for _, p := range pendings {
			// a. 创建个人租户
			tenant := dao.Tenant{
				Name:   p.username + "的个人空间",
				Code:   p.code,
				Status: 1,
				Ctime:  now,
				Utime:  now,
			}
			if err := tx.Create(&tenant).Error; err != nil {
				return fmt.Errorf("创建 %s 个人空间失败: %w", p.username, err)
			}

			// b. 建立成员关系
			if err := tx.Create(&dao.Membership{
				TenantID: tenant.ID,
				UserID:   p.userID,
				Ctime:    now,
			}).Error; err != nil {
				return fmt.Errorf("创建 %s 成员关系失败: %w", p.username, err)
			}

			// c. 授予 admin 角色
			if err := tx.Create(&dao.CasbinRule{
				Ptype: "g",
				V0:    "user:" + p.username,
				V1:    "role:admin",
				V2:    strconv.FormatInt(tenant.ID, 10),
				V3:    strconv.FormatInt(now, 10),
			}).Error; err != nil {
				return fmt.Errorf("创建 %s 权限规则失败: %w", p.username, err)
			}
		}
		log.Printf("[post-check] 个人租户空间初始化完成: %d 个", len(pendings))
		return nil
	})
}

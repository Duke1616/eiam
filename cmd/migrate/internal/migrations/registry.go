package migrations

import "github.com/Duke1616/eiam/cmd/migrate/internal/migration"

// All 按外键和业务依赖顺序返回所有迁移任务。
func All(encryptionKey, encryptionVersion string) []migration.Migrator {
	migrators := []migration.Migrator{
		NewDepartmentMigrator(),
		NewUserMigrator(encryptionKey, encryptionVersion),
		NewUserProfileMigrator(),
		NewUserIdentityMigrator(),
		NewUserMembershipMigrator(),
		NewUserDepartmentMigrator(),
	}
	return migrators
}

// PreHooks 返回迁移前执行的钩子（冲突检测与数据清理）。
func PreHooks() []migration.Hook {
	return []migration.Hook{
		NewUserPreMigrateHook(),
	}
}

// PostHooks 返回迁移后执行的钩子（数据补偿与一致性修复）。
func PostHooks() []migration.Hook {
	return []migration.Hook{
		NewUserPostMigrateHook(),
	}
}

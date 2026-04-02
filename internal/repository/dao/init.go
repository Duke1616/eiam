package dao

import "gorm.io/gorm"

func InitTables(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&UserProfile{},
		&UserIdentity{},
		&Tenant{},
		&Membership{},
		&Role{},
		&Permission{},
		&PermissionBinding{},
		&Menu{},
		&API{},
	)
}

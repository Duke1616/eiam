package dao

import "gorm.io/gorm"

func InitTables(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&UserInfo{},
		&UserIdentity{},
		&Tenant{},
		&Member{},
		&Role{},
		&Permission{},
		&PermissionBinding{},
		&Menu{},
		&API{},
	)
}

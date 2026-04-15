package dao

import (
	gormAdapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"
)

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
		&Policy{},
		&PolicyAssignment{},
		&Menu{},
		&API{},
		&Service{},
		&gormAdapter.CasbinRule{},
	)
}

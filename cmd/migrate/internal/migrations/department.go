package migrations

import (
	"github.com/Duke1616/eiam/pkg/migration"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/sqlx"
)

const (
	deptCollectionName = "c_department"
)

type mongoDepartment struct {
	Id         int64    `bson:"id"`
	Pid        int64    `bson:"pid"`
	Name       string   `bson:"name"`
	Sort       int64    `bson:"sort"`
	Leaders    []string `bson:"leaders"`
	MainLeader string   `bson:"main_leader"`
	Ctime      int64    `bson:"ctime"`
	Utime      int64    `bson:"utime"`
}

type deptMigrator struct{}

func NewDepartmentMigrator() migration.Migrator {
	return migration.NewMongoMigrator[mongoDepartment, dao.Department](deptMigrator{})
}

func (deptMigrator) Name() string           { return "department" }
func (deptMigrator) CollectionName() string { return deptCollectionName }
func (deptMigrator) Convert(src mongoDepartment) dao.Department {
	return dao.Department{
		Id:         src.Id,
		TenantId:   defaultTenantID,
		ParentId:   src.Pid,
		Name:       src.Name,
		Sort:       src.Sort,
		Leaders:    sqlx.JSONColumn[[]string]{Val: src.Leaders, Valid: true},
		MainLeader: src.MainLeader,
		Ctime:      src.Ctime,
		Utime:      src.Utime,
	}
}

package ioc

import (
	"database/sql"

	"github.com/Duke1616/eiam/deploy/migrations"
	"github.com/gotomicro/ego/core/elog"
	"github.com/pressly/goose/v3"
	"gorm.io/gorm"
)

// RunMigrations 在应用启动时自动执行所有待执行的 SQL 迁移。
// 如果迁移过程中任何一步报错（比如 SQL 语法错误、数据入库冲突等），服务将 Panic 阻断启动，保护上层一致性。
func RunMigrations(db *gorm.DB) {
	sqlDB, err := db.DB()
	if err != nil {
		panic("获取 *sql.DB 实例失败: " + err.Error())
	}

	if err = runGooseMigrations(sqlDB, db.Dialector.Name()); err != nil {
		panic("数据库迁移失败（请检查 deploy/migrations/ 下的脚本）: " + err.Error())
	}

	elog.DefaultLogger.Info("数据库多租户初始化迁移任务已完成")
}

func runGooseMigrations(sqlDB *sql.DB, dialect string) error {
	// 设置嵌入式文件系统作为 goose 的数据源
	goose.SetBaseFS(migrations.FS)

	// 动态配置方言，以兼容 MySQL 和 Sqlite (测试环境)
	if err := goose.SetDialect(dialect); err != nil {
		return err
	}

	// 执行 Up 命令，将本地 SQL 脚本全速推送到目标库
	// "." 代表 embed.FS 内的相对目录（migrations.FS 对应的 path）
	return goose.Up(sqlDB, ".")
}

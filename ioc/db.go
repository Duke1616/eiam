package ioc

import (
	"context"
	"database/sql"
	"log"
	"os"
	"time"

	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/spf13/viper"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"

	"github.com/Duke1616/eiam/pkg/gormx"
	"github.com/ecodeclub/ekit/retry"
)

func InitDB() *gorm.DB {
	db := InitDBWithoutMigrate()

	// AutoMigrate 创建/更新表结构
	if err := dao.InitTables(db); err != nil {
		panic(err)
	}

	// RunMigrations 执行迁移升级 (含 Seed)
	if err := RunMigrations(db); err != nil {
		panic(err)
	}

	return db
}

// InitDBWithoutMigrate 初始化数据库连接并配置基础插件，但不执行 DDL/DML 迁移
func InitDBWithoutMigrate() *gorm.DB {
	dsn := viper.GetString("mysql.dsn")
	WaitForDBSetup(dsn)

	myLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             2 * time.Second,
			LogLevel:                  logger.LogLevel(4),
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
		Logger: myLogger,
	})
	if err != nil {
		panic(err)
	}

	// 注册多租户隔离插件
	if err = db.Use(gormx.NewTenantPlugin()); err != nil {
		panic(err)
	}

	return db
}

func WaitForDBSetup(dsn string) {
	sqlDB, err := sql.Open("mysql", dsn)
	if err != nil {
		panic(err)
	}
	const maxInterval = 10 * time.Second
	const maxRetries = 10
	strategy, err := retry.NewExponentialBackoffRetryStrategy(time.Second, maxInterval, maxRetries)
	if err != nil {
		panic(err)
	}

	const timeout = 5 * time.Second
	for {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		err = sqlDB.PingContext(ctx)
		cancel()
		if err == nil {
			break
		}
		next, ok := strategy.Next()
		if !ok {
			panic("WaitForDBSetup 重试失败......")
		}
		time.Sleep(next)
	}
}

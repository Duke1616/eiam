package migration

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"gorm.io/gorm"
)

// Config 通用迁移配置
type Config struct {
	MongoDSN           string
	MongoDBName        string
	MySQLSrcDSN        string
	MySQLDstDSN        string
	BatchSize          int
	Timeout            time.Duration
	AutoMigrate        bool
	ResetAutoIncrement bool
	Truncate           bool
	DryRun             bool
}

// MigrationEnv 迁移环境变量，承载数据源连接
type MigrationEnv struct {
	MongoDB         *mongo.Database
	MySQLSrc        *gorm.DB // 可选，由 config 决定是否初始化
	MySQLDst        *gorm.DB
	BatchSize       int
	DryRun          bool
	DefaultTenantID *int64 // 默认租户 ID 指针，若设置则批量写入时自动覆盖
}

// Result 单次迁移结果记录
type Result struct {
	Read      int64
	Converted int64
	Written   int64
}

// Migrator 迁移执行者接口
type Migrator interface {
	Name() string
	Destination() any
	Migrate(ctx context.Context, env MigrationEnv) (Result, error)
}

// Hook 迁移生命周期钩子
type Hook func(ctx context.Context, env MigrationEnv) error

// Reader 泛型数据源读取接口
type Reader[S any] interface {
	ReadNext(ctx context.Context, env MigrationEnv) ([]S, error)
	Close(ctx context.Context) error
}

// Transformer 泛型数据模型转换接口
type Transformer[S any, D any] interface {
	Transform(src S) ([]D, error)
}

// Writer 泛型数据写入接口
type Writer[D any] interface {
	Write(ctx context.Context, env MigrationEnv, batch []D) (int64, error)
}

// MongoMigration 1:1 的 MongoDB 到 MySQL 迁移规约
type MongoMigration[S any, D any] interface {
	Name() string
	CollectionName() string
	Convert(src S) D
}

// MongoMigrationMany 1:N 的 MongoDB 到 MySQL 迁移规约
type MongoMigrationMany[S any, D any] interface {
	Name() string
	CollectionName() string
	ConvertMany(src S) []D
}

// MySQLMigration 1:1 的 MySQL 到 MySQL 迁移规约 (支持 eflow)
type MySQLMigration[T any] interface {
	Name() string
	Source() any
	Destination() any
}

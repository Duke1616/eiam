package migration

import (
	"context"
	"fmt"
	"log"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// MigrationEnv 保存单次迁移执行期间共享的数据源连接。
type MigrationEnv struct {
	MongoDB   *mongo.Database
	MySQLDst  *gorm.DB
	BatchSize int
	DryRun    bool
}

// Result 记录单个迁移任务的处理结果。
type Result struct {
	Read      int64
	Converted int64
	Written   int64
}

// Migrator 表示一个可编排的数据迁移任务。
type Migrator interface {
	Name() string
	Destination() any
	Migrate(ctx context.Context, env MigrationEnv) (Result, error)
}

// Hook 在迁移前/后执行的回调函数，用于冲突检测与数据补偿。
type Hook func(ctx context.Context, env MigrationEnv) error

// MongoMigration 定义 1:1 的 MongoDB 源到 MySQL 目标的表级迁移规格。
type MongoMigration[S any, D any] interface {
	Name() string
	CollectionName() string
	Convert(src S) D
}

type mongoMigrator[M any, D any] struct {
	migration MongoMigration[M, D]
}

// NewMongoMigrator 使用 1:1 迁移规格创建 MongoDB 源迁移器。
func NewMongoMigrator[M any, D any](migration MongoMigration[M, D]) Migrator {
	return &mongoMigrator[M, D]{migration: migration}
}

func (m *mongoMigrator[M, D]) Name() string     { return m.migration.Name() }
func (m *mongoMigrator[M, D]) Destination() any { return new(D) }

func (m *mongoMigrator[M, D]) Migrate(ctx context.Context, env MigrationEnv) (Result, error) {
	cursor, err := env.MongoDB.Collection(m.migration.CollectionName()).Find(ctx, bson.M{})
	if err != nil {
		return Result{}, err
	}
	defer cursor.Close(ctx)

	batch := make([]D, 0, env.BatchSize)
	var result Result
	for cursor.Next(ctx) {
		var src M
		if err = cursor.Decode(&src); err != nil {
			return result, err
		}
		result.Read++
		batch = append(batch, m.migration.Convert(src))
		if len(batch) >= env.BatchSize {
			written, err := writeBatch(ctx, env, batch)
			if err != nil {
				return result, err
			}
			result.Converted += int64(len(batch))
			result.Written += written
			batch = batch[:0]
		}
	}
	if err = cursor.Err(); err != nil {
		return result, err
	}
	written, err := writeBatch(ctx, env, batch)
	if err != nil {
		return result, err
	}
	result.Converted += int64(len(batch))
	result.Written += written
	if result.Read == 0 {
		log.Printf("[%s] 源集合 %s 为空", m.Name(), m.migration.CollectionName())
	}
	return result, nil
}

// MongoMigrationMany 定义 1:N 的 MongoDB 源到 MySQL 目标的表级迁移规格。
// 一条源数据可转换为目标表的多条记录，适用于拆表场景。
type MongoMigrationMany[S any, D any] interface {
	Name() string
	CollectionName() string
	ConvertMany(src S) []D
}

type mongoMigratorMany[M any, D any] struct {
	migration MongoMigrationMany[M, D]
}

// NewMongoMigratorMany 使用 1:N 迁移规格创建 MongoDB 源迁移器。
func NewMongoMigratorMany[M any, D any](migration MongoMigrationMany[M, D]) Migrator {
	return &mongoMigratorMany[M, D]{migration: migration}
}

func (m *mongoMigratorMany[M, D]) Name() string     { return m.migration.Name() }
func (m *mongoMigratorMany[M, D]) Destination() any { return new(D) }

func (m *mongoMigratorMany[M, D]) Migrate(ctx context.Context, env MigrationEnv) (Result, error) {
	cursor, err := env.MongoDB.Collection(m.migration.CollectionName()).Find(ctx, bson.M{})
	if err != nil {
		return Result{}, err
	}
	defer cursor.Close(ctx)

	batch := make([]D, 0, env.BatchSize)
	var result Result
	for cursor.Next(ctx) {
		var src M
		if err = cursor.Decode(&src); err != nil {
			return result, err
		}
		result.Read++
		batch = append(batch, m.migration.ConvertMany(src)...)
		if len(batch) >= env.BatchSize {
			written, err := writeBatch(ctx, env, batch)
			if err != nil {
				return result, err
			}
			result.Converted += int64(len(batch))
			result.Written += written
			batch = batch[:0]
		}
	}
	if err = cursor.Err(); err != nil {
		return result, err
	}
	written, err := writeBatch(ctx, env, batch)
	if err != nil {
		return result, err
	}
	result.Converted += int64(len(batch))
	result.Written += written
	if result.Read == 0 {
		log.Printf("[%s] 源集合 %s 为空", m.Name(), m.migration.CollectionName())
	}
	return result, nil
}

func writeBatch[D any](ctx context.Context, env MigrationEnv, records []D) (int64, error) {
	if len(records) == 0 {
		return 0, nil
	}
	if env.DryRun {
		return 0, nil
	}
	err := env.MySQLDst.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		CreateInBatches(records, env.BatchSize).Error
	if err != nil {
		return 0, err
	}
	return int64(len(records)), nil
}

func tableName(db *gorm.DB, model any) (string, error) {
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(model); err != nil {
		return "", fmt.Errorf("解析目标表名失败: %w", err)
	}
	if stmt.Schema == nil {
		return "", fmt.Errorf("解析目标表名失败: schema 为空")
	}
	if stmt.Schema.Table == "" {
		return "", fmt.Errorf("解析目标表名失败: 表名为空")
	}
	return stmt.Schema.Table, nil
}

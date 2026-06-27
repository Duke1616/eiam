package migration

import (
	"context"
	"errors"
	"fmt"
	"log"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// mongoReader 具体的通用 MongoDB 读取实现
type mongoReader[S any] struct {
	collectionName string
	cursor         *mongo.Cursor
}

func (r *mongoReader[S]) ReadNext(ctx context.Context, env MigrationEnv) ([]S, error) {
	if r.cursor == nil {
		cursor, err := env.MongoDB.Collection(r.collectionName).Find(ctx, bson.M{})
		if err != nil {
			return nil, err
		}
		r.cursor = cursor
	}

	batch := make([]S, 0, env.BatchSize)
	for len(batch) < env.BatchSize && r.cursor.Next(ctx) {
		var item S
		if err := r.cursor.Decode(&item); err != nil {
			return nil, err
		}
		batch = append(batch, item)
	}
	if err := r.cursor.Err(); err != nil {
		return nil, err
	}
	return batch, nil
}

func (r *mongoReader[S]) Close(ctx context.Context) error {
	if r.cursor != nil {
		return r.cursor.Close(ctx)
	}
	return nil
}

// mongoTransformer 适配 1:1 MongoDB 转换的包装器
type mongoTransformer[S any, D any] struct {
	convert func(S) D
}

func (t *mongoTransformer[S, D]) Transform(src S) ([]D, error) {
	return []D{t.convert(src)}, nil
}

// mongoTransformerMany 适配 1:N MongoDB 转换的包装器
type mongoTransformerMany[S any, D any] struct {
	convertMany func(S) []D
}

func (t *mongoTransformerMany[S, D]) Transform(src S) ([]D, error) {
	return t.convertMany(src), nil
}

type mongoAutoIncrementSyncer struct {
	collectionName string
	dstModel       any
}

func (s *mongoAutoIncrementSyncer) SyncAutoIncrement(ctx context.Context, env MigrationEnv) error {
	if env.MongoDB == nil || env.MySQLDst == nil {
		return nil
	}

	table, err := tableName(env.MySQLDst, s.dstModel)
	if err != nil {
		return fmt.Errorf("同步自增值解析目标表名失败: %w", err)
	}

	// 1. 从 MongoDB 读取自增值
	coll := env.MongoDB.Collection("c_id_generator")
	var record struct {
		Name   string `bson:"name"`
		NextID int64  `bson:"next_id"`
	}

	err = coll.FindOne(ctx, bson.M{"name": s.collectionName}).Decode(&record)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil
		}
		return fmt.Errorf("从 MongoDB 获取 [%s] 的自增起点失败: %w", s.collectionName, err)
	}

	if record.NextID <= 1 {
		return nil
	}

	// 2. 读取目标 MySQL 当前最大 ID
	var maxID int64
	env.MySQLDst.WithContext(ctx).Raw(
		fmt.Sprintf("SELECT COALESCE(MAX(id), 0) FROM %s", quoteIdentifier(table)),
	).Scan(&maxID)

	// 2.5 读取目标库当前的 AUTO_INCREMENT 状态值，防止重新同步时将自增起点往回调低
	dstDBName := env.MySQLDst.Migrator().CurrentDatabase()
	var dstAutoInc *int64
	_ = env.MySQLDst.WithContext(ctx).Raw(
		"SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?",
		dstDBName, table,
	).Scan(&dstAutoInc)

	// 3. 取三者较大值（保证绝对只增不减）
	newAutoInc := record.NextID
	if maxID+1 > newAutoInc {
		newAutoInc = maxID + 1
	}
	if dstAutoInc != nil && *dstAutoInc > newAutoInc {
		newAutoInc = *dstAutoInc
	}

	// 4. 执行设置
	log.Printf("[%s] 调整自增值: MongoDB=%d, MySQL最大ID=%d, 最终设置为=%d",
		table, record.NextID, maxID, newAutoInc)

	err = env.MySQLDst.WithContext(ctx).Exec(
		fmt.Sprintf("ALTER TABLE %s AUTO_INCREMENT = %d", quoteIdentifier(table), newAutoInc),
	).Error
	if err != nil {
		return fmt.Errorf("同步表 %s 自增起点失败: %w", table, err)
	}

	return nil
}

// NewMongoMigrator 通过 1:1 规约创建通用迁移器
func NewMongoMigrator[S any, D any](spec MongoMigration[S, D]) Migrator {
	var dst D
	return &genericMigrator[S, D]{
		name:        spec.Name(),
		reader:      &mongoReader[S]{collectionName: spec.CollectionName()},
		transformer: &mongoTransformer[S, D]{convert: spec.Convert},
		writer:      &mysqlWriter[D]{},
		autoIncSyncer: &mongoAutoIncrementSyncer{
			collectionName: spec.CollectionName(),
			dstModel:       &dst,
		},
	}
}

// NewMongoMigratorMany 通过 1:N 规约创建通用迁移器
func NewMongoMigratorMany[S any, D any](spec MongoMigrationMany[S, D]) Migrator {
	var dst D
	return &genericMigrator[S, D]{
		name:        spec.Name(),
		reader:      &mongoReader[S]{collectionName: spec.CollectionName()},
		transformer: &mongoTransformerMany[S, D]{convertMany: spec.ConvertMany},
		writer:      &mysqlWriter[D]{},
		autoIncSyncer: &mongoAutoIncrementSyncer{
			collectionName: spec.CollectionName(),
			dstModel:       &dst,
		},
	}
}

package migration

import (
	"context"

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

// NewMongoMigrator 通过 1:1 规约创建通用迁移器
func NewMongoMigrator[S any, D any](spec MongoMigration[S, D]) Migrator {
	return &genericMigrator[S, D]{
		name:        spec.Name(),
		reader:      &mongoReader[S]{collectionName: spec.CollectionName()},
		transformer: &mongoTransformer[S, D]{convert: spec.Convert},
		writer:      &mysqlWriter[D]{},
	}
}

// NewMongoMigratorMany 通过 1:N 规约创建通用迁移器
func NewMongoMigratorMany[S any, D any](spec MongoMigrationMany[S, D]) Migrator {
	return &genericMigrator[S, D]{
		name:        spec.Name(),
		reader:      &mongoReader[S]{collectionName: spec.CollectionName()},
		transformer: &mongoTransformerMany[S, D]{convertMany: spec.ConvertMany},
		writer:      &mysqlWriter[D]{},
	}
}

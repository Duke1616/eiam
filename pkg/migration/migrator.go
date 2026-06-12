package migration

import (
	"context"
	"log"
)

// genericMigrator 通用泛型迁移驱动器
type genericMigrator[S any, D any] struct {
	name          string
	reader        Reader[S]
	transformer   Transformer[S, D]
	writer        Writer[D]
	autoIncSyncer IAutoIncrementSyncer
}

func (m *genericMigrator[S, D]) Name() string     { return m.name }
func (m *genericMigrator[S, D]) Destination() any { return new(D) }

// SyncAutoIncrement 实现 IAutoIncrementSyncer 接口
func (m *genericMigrator[S, D]) SyncAutoIncrement(ctx context.Context, env MigrationEnv) error {
	if m.autoIncSyncer != nil {
		return m.autoIncSyncer.SyncAutoIncrement(ctx, env)
	}
	return nil
}

func (m *genericMigrator[S, D]) Migrate(ctx context.Context, env MigrationEnv) (Result, error) {
	defer m.reader.Close(ctx)
	var result Result

	for {
		srcBatch, err := m.reader.ReadNext(ctx, env)
		if err != nil {
			return result, err
		}
		if len(srcBatch) == 0 {
			break
		}
		result.Read += int64(len(srcBatch))

		dstBatch := make([]D, 0, len(srcBatch))
		for _, src := range srcBatch {
			transformed, err := m.transformer.Transform(src)
			if err != nil {
				return result, err
			}
			dstBatch = append(dstBatch, transformed...)
		}

		written, err := m.writer.Write(ctx, env, dstBatch)
		if err != nil {
			return result, err
		}
		result.Converted += int64(len(dstBatch))
		result.Written += written
	}

	if result.Read == 0 {
		log.Printf("[%s] 未读取到任何源数据", m.name)
	}
	return result, nil
}

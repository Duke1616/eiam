package migration

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"strconv"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// mysqlReader 具体的通用 MySQL 读取实现 (支持 eflow)
type mysqlReader[S any] struct {
	model  any
	offset int
}

func (r *mysqlReader[S]) ReadNext(ctx context.Context, env MigrationEnv) ([]S, error) {
	var batch []S
	err := env.MySQLSrc.WithContext(ctx).
		Model(r.model).
		Order("id asc").
		Offset(r.offset).
		Limit(env.BatchSize).
		Find(&batch).Error
	if err != nil {
		return nil, err
	}
	r.offset += len(batch)
	return batch, nil
}

func (r *mysqlReader[S]) Close(ctx context.Context) error {
	return nil
}

// mysqlWriter 具体的通用 MySQL 写入实现
type mysqlWriter[D any] struct{}

func (w *mysqlWriter[D]) Write(ctx context.Context, env MigrationEnv, batch []D) (int64, error) {
	if len(batch) == 0 {
		return 0, nil
	}
	if env.DryRun {
		return 0, nil
	}
	if env.DefaultTenantID != nil {
		for i := range batch {
			applyDefaultTenant(&batch[i], *env.DefaultTenantID)
		}
	}
	err := env.MySQLDst.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		CreateInBatches(batch, env.BatchSize).Error
	if err != nil {
		return 0, err
	}
	return int64(len(batch)), nil
}

// noopTransformer 无转换包装器 (MySQL ➔ MySQL 同类型迁移)
type noopTransformer[T any] struct{}

func (t *noopTransformer[T]) Transform(src T) ([]T, error) {
	return []T{src}, nil
}

type mysqlAutoIncrementSyncer struct {
	dstModel any
}

func (s *mysqlAutoIncrementSyncer) SyncAutoIncrement(ctx context.Context, env MigrationEnv) error {
	if env.MySQLSrc == nil || env.MySQLDst == nil {
		return nil
	}

	table, err := tableName(env.MySQLDst, s.dstModel)
	if err != nil {
		return fmt.Errorf("同步自增值解析目标表名失败: %w", err)
	}

	// 1. 读取源库自增值
	srcDBName := env.MySQLSrc.Migrator().CurrentDatabase()
	var srcAutoInc *int64
	err = env.MySQLSrc.WithContext(ctx).Raw(
		"SELECT AUTO_INCREMENT FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?",
		srcDBName, table,
	).Scan(&srcAutoInc).Error
	if err != nil || srcAutoInc == nil || *srcAutoInc <= 1 {
		return nil
	}

	// 2. 读取目标库当前最大ID
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

	// 3. 取三者中最大值作为目标自增值（保证绝对只增不减）
	newAutoInc := *srcAutoInc
	if maxID+1 > newAutoInc {
		newAutoInc = maxID + 1
	}
	if dstAutoInc != nil && *dstAutoInc > newAutoInc {
		newAutoInc = *dstAutoInc
	}

	// 4. 执行设置
	err = env.MySQLDst.WithContext(ctx).Exec(
		fmt.Sprintf("ALTER TABLE %s AUTO_INCREMENT = %d", quoteIdentifier(table), newAutoInc),
	).Error
	if err != nil {
		return fmt.Errorf("同步表 %s 自增起点失败: %w", table, err)
	}

	log.Printf("[%s] 自增值已同步为: %d", table, newAutoInc)
	return nil
}

// NewMySQLMigrator 通过 MySQL 规约创建通用迁移器
func NewMySQLMigrator[T any](spec MySQLMigration[T]) Migrator {
	return &genericMigrator[T, T]{
		name:          spec.Name(),
		reader:        &mysqlReader[T]{model: spec.Source()},
		transformer:   &noopTransformer[T]{},
		writer:        &mysqlWriter[T]{},
		autoIncSyncer: &mysqlAutoIncrementSyncer{dstModel: spec.Destination()},
	}
}

// applyDefaultTenant 反射覆写租户 ID
func applyDefaultTenant(dst any, tenantID int64) {
	v := reflect.ValueOf(dst)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	field := v.FieldByName("TenantID")
	if field.IsValid() && field.CanSet() {
		switch field.Kind() {
		case reflect.String:
			field.SetString(strconv.FormatInt(tenantID, 10))
		case reflect.Int, reflect.Int64:
			field.SetInt(tenantID)
		default:
		}
	}
}

// tableName 辅助解析目标表名
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

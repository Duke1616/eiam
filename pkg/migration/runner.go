package migration

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

// MigrationRecord 迁移历史记录实体
type MigrationRecord struct {
	Id        int64     `gorm:"primaryKey;column:id;type:bigint;autoIncrement"`
	Name      string    `gorm:"column:name;type:varchar(128);uniqueIndex;not null;comment:'迁移任务名称'"`
	Read      int64     `gorm:"column:read_count;type:bigint;not null;comment:'读取源数据条数'"`
	Converted int64     `gorm:"column:converted_count;type:bigint;not null;comment:'转换成功条数'"`
	Written   int64     `gorm:"column:written_count;type:bigint;not null;comment:'写入目标表条数'"`
	Ctime     time.Time `gorm:"column:ctime;type:datetime;not null;comment:'迁移开始时间'"`
	Utime     time.Time `gorm:"column:utime;type:datetime;not null;comment:'迁移完成时间'"`
}

// Runner 负责连接数据源，并按顺序执行一组迁移任务。
type Runner struct {
	cfg             Config
	migrators       []Migrator
	preHooks        []Hook
	postHooks       []Hook
	autoMigrateFunc func(db *gorm.DB) error
	defaultTenantID *int64
}

// NewRunner 创建迁移执行器。
func NewRunner(cfg Config, migrators []Migrator, options ...RunnerOption) *Runner {
	r := &Runner{cfg: cfg, migrators: migrators}
	for _, opt := range options {
		opt(r)
	}
	return r
}

// RunnerOption 配置 Runner 的可选参数。
type RunnerOption func(*Runner)

// WithPreHooks 注册迁移前执行的钩子。
func WithPreHooks(hooks ...Hook) RunnerOption {
	return func(r *Runner) { r.preHooks = append(r.preHooks, hooks...) }
}

// WithPostHooks 注册迁移后执行的钩子。
func WithPostHooks(hooks ...Hook) RunnerOption {
	return func(r *Runner) { r.postHooks = append(r.postHooks, hooks...) }
}

// WithAutoMigrateFunc 注册目标数据库结构初始化函数。
func WithAutoMigrateFunc(fn func(db *gorm.DB) error) RunnerOption {
	return func(r *Runner) { r.autoMigrateFunc = fn }
}

// WithDefaultTenantID 注册默认租户 ID（执行迁移时如果目标表结构体有 TenantID 则反射覆写）。
func WithDefaultTenantID(id int64) RunnerOption {
	return func(r *Runner) { r.defaultTenantID = &id }
}

// Run 执行完整迁移流程。
func (r *Runner) Run(ctx context.Context) error {
	mongoClient, err := mongo.Connect(options.Client().ApplyURI(r.cfg.MongoDSN))
	if err != nil {
		return fmt.Errorf("连接源端 MongoDB 失败: %w", err)
	}
	defer func() {
		if err := mongoClient.Disconnect(context.Background()); err != nil {
			log.Printf("warning: 关闭 MongoDB 连接失败: %v", err)
		}
	}()
	if err = mongoClient.Ping(ctx, readpref.Primary()); err != nil {
		return fmt.Errorf("探测源端 MongoDB 失败: %w", err)
	}

	var mysqlSRC *gorm.DB
	if r.cfg.MySQLSrcDSN != "" {
		mysqlSRC, err = openMySQL(r.cfg.MySQLSrcDSN)
		if err != nil {
			return fmt.Errorf("连接源端 MySQL 失败: %w", err)
		}
		if err = pingMySQL(ctx, mysqlSRC); err != nil {
			closeMySQL("源端 MySQL", mysqlSRC)
			return fmt.Errorf("探测源端 MySQL 失败: %w", err)
		}
		defer closeMySQL("源端 MySQL", mysqlSRC)
	}

	mysqlDST, err := openMySQL(r.cfg.MySQLDstDSN)
	if err != nil {
		return fmt.Errorf("连接目标端 MySQL 失败: %w", err)
	}
	if err = pingMySQL(ctx, mysqlDST); err != nil {
		closeMySQL("目标端 MySQL", mysqlDST)
		return fmt.Errorf("探测目标端 MySQL 失败: %w", err)
	}
	defer closeMySQL("目标端 MySQL", mysqlDST)

	env := MigrationEnv{
		MongoDB:         mongoClient.Database(r.cfg.MongoDBName),
		MySQLSrc:        mysqlSRC,
		MySQLDst:        mysqlDST,
		BatchSize:       r.cfg.BatchSize,
		DryRun:          r.cfg.DryRun,
		DefaultTenantID: r.defaultTenantID,
	}

	// 始终自动初始化迁移状态控制记录表
	if !r.cfg.DryRun {
		if err = mysqlDST.AutoMigrate(&MigrationRecord{}); err != nil {
			return fmt.Errorf("初始化迁移记录表失败: %w", err)
		}
	}

	if r.cfg.AutoMigrate && !r.cfg.DryRun && r.autoMigrateFunc != nil {
		log.Println("正在初始化目标端表结构")
		if err = r.autoMigrateFunc(mysqlDST); err != nil {
			return fmt.Errorf("初始化目标端表结构失败: %w", err)
		}
	}

	if r.cfg.Truncate && !r.cfg.DryRun {
		if err = r.truncateDestinations(ctx, mysqlDST); err != nil {
			return err
		}
	}

	log.Printf("开始迁移: batch_size=%d dry_run=%t", r.cfg.BatchSize, r.cfg.DryRun)

	// Pre-hooks: 冲突检测与数据清理
	for _, hook := range r.preHooks {
		if err = hook(ctx, env); err != nil {
			return fmt.Errorf("迁移前钩子失败: %w", err)
		}
	}

	for _, migrator := range r.migrators {
		// 检查该任务是否已成功执行，已执行则跳过
		if skipped, err1 := r.shouldSkip(mysqlDST, migrator); err1 != nil {
			return err1
		} else if skipped {
			continue
		}

		startTime := time.Now()
		log.Printf("正在迁移 %s", migrator.Name())
		result, err := migrator.Migrate(ctx, env)
		if err != nil {
			return fmt.Errorf("迁移 %s 失败: %w", migrator.Name(), err)
		}
		log.Printf("完成 %s: read=%d converted=%d written=%d", migrator.Name(), result.Read, result.Converted, result.Written)

		if !r.cfg.DryRun {
			newRecord := MigrationRecord{
				Name:      migrator.Name(),
				Read:      result.Read,
				Converted: result.Converted,
				Written:   result.Written,
				Ctime:     startTime,
				Utime:     time.Now(),
			}
			if err = mysqlDST.Create(&newRecord).Error; err != nil {
				return fmt.Errorf("保存迁移历史记录 [%s] 失败: %w", migrator.Name(), err)
			}
		}
	}

	// Post-hooks: 数据补偿与一致性修复
	for _, hook := range r.postHooks {
		if err = hook(ctx, env); err != nil {
			return fmt.Errorf("迁移后钩子失败: %w", err)
		}
	}

	if r.cfg.ResetAutoIncrement && !r.cfg.DryRun {
		if err = r.resetAutoIncrement(ctx, mysqlDST); err != nil {
			return err
		}
	}
	return nil
}

// shouldSkip 判断指定任务是否已存在执行成功的历史，存在则跳过以达到幂等性
func (r *Runner) shouldSkip(db *gorm.DB, migrator Migrator) (bool, error) {
	if r.cfg.DryRun {
		return false, nil
	}

	if r.cfg.Force {
		if err := db.Where("name = ?", migrator.Name()).Delete(&MigrationRecord{}).Error; err != nil {
			return false, fmt.Errorf("强制重新迁移时清理旧记录 [%s] 失败: %w", migrator.Name(), err)
		}
		return false, nil
	}

	var record MigrationRecord
	err := db.Where("name = ?", migrator.Name()).First(&record).Error
	if err == nil {
		log.Printf("迁移任务 [%s] 已经于 %s 执行成功过 (读取:%d 写入:%d)，直接跳过。若想重新执行，请在数据库中删除该任务对应的记录。",
			migrator.Name(), record.Utime.Format("2006-01-02 15:04:05"), record.Read, record.Written)
		return true, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	return false, fmt.Errorf("查询迁移历史记录 [%s] 失败: %w", migrator.Name(), err)
}

func openMySQL(dsn string) (*gorm.DB, error) {
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             3 * time.Second,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)
	return gorm.Open(mysql.Open(dsn), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{SingularTable: true},
		Logger:         newLogger,
	})
}

func pingMySQL(ctx context.Context, db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

func closeMySQL(name string, db *gorm.DB) {
	sqlDB, err := db.DB()
	if err != nil {
		log.Printf("warning: 获取 %s 连接句柄失败: %v", name, err)
		return
	}
	if err = sqlDB.Close(); err != nil {
		log.Printf("warning: 关闭 %s 连接失败: %v", name, err)
	}
}

func (r *Runner) truncateDestinations(ctx context.Context, db *gorm.DB) error {
	for i := len(r.migrators) - 1; i >= 0; i-- {
		table, err := tableName(db, r.migrators[i].Destination())
		if err != nil {
			return err
		}
		log.Printf("正在清空目标表 %s", table)
		if err = db.WithContext(ctx).Exec("TRUNCATE TABLE " + quoteIdentifier(table)).Error; err != nil {
			return fmt.Errorf("清空目标表 %s 失败: %w", table, err)
		}
	}

	log.Println("正在清空迁移历史记录表")
	if err := db.WithContext(ctx).Exec("TRUNCATE TABLE migration_record").Error; err != nil {
		log.Printf("warning: 清空迁移历史记录表失败: %v", err)
	}
	return nil
}

func (r *Runner) resetAutoIncrement(ctx context.Context, db *gorm.DB) error {
	for _, migrator := range r.migrators {
		table, err := tableName(db, migrator.Destination())
		if err != nil {
			return err
		}
		if err = db.WithContext(ctx).Exec("ALTER TABLE " + quoteIdentifier(table) + " AUTO_INCREMENT = 1").Error; err != nil {
			return fmt.Errorf("重置目标表 %s 自增序列失败: %w", table, err)
		}
		log.Printf("已重置目标表 %s 自增序列", table)
	}
	return nil
}

func quoteIdentifier(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

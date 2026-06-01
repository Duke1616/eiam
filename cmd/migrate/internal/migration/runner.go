package migration

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/Duke1616/eiam/cmd/migrate/internal/config"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

// Runner 负责连接数据源，并按顺序执行一组迁移任务。
type Runner struct {
	cfg       config.Config
	migrators []Migrator
	preHooks  []Hook
	postHooks []Hook
}

// NewRunner 创建迁移执行器。
func NewRunner(cfg config.Config, migrators []Migrator, options ...RunnerOption) *Runner {
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

	mysqlDST, err := openMySQL(r.cfg.MySQLDstDSN)
	if err != nil {
		return fmt.Errorf("连接目标端 MySQL 失败: %w", err)
	}
	if err = pingMySQL(ctx, mysqlDST); err != nil {
		return fmt.Errorf("探测目标端 MySQL 失败: %w", err)
	}
	defer closeMySQL("目标端 MySQL", mysqlDST)

	env := MigrationEnv{
		MongoDB:   mongoClient.Database(r.cfg.MongoDBName),
		MySQLDst:  mysqlDST,
		BatchSize: r.cfg.BatchSize,
		DryRun:    r.cfg.DryRun,
	}

	if r.cfg.AutoMigrate && !r.cfg.DryRun {
		log.Println("正在初始化目标端表结构")
		if err = dao.InitTables(mysqlDST); err != nil {
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
		log.Printf("正在迁移 %s", migrator.Name())
		result, err := migrator.Migrate(ctx, env)
		if err != nil {
			return fmt.Errorf("迁移 %s 失败: %w", migrator.Name(), err)
		}
		log.Printf("完成 %s: read=%d converted=%d written=%d", migrator.Name(), result.Read, result.Converted, result.Written)
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

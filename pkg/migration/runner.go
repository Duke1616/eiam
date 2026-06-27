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

// IRecordStore 定义了迁移历史记录的存储层接口
type IRecordStore interface {
	AutoMigrate(ctx context.Context) error
	Get(ctx context.Context, name string) (*MigrationRecord, error)
	Delete(ctx context.Context, name string) error
	Save(ctx context.Context, record *MigrationRecord) error
	Clear(ctx context.Context) error
}

type gormRecordStore struct {
	db *gorm.DB
}

func NewGORMRecordStore(db *gorm.DB) IRecordStore {
	return &gormRecordStore{db: db}
}

func (s *gormRecordStore) AutoMigrate(ctx context.Context) error {
	return s.db.WithContext(ctx).AutoMigrate(&MigrationRecord{})
}

func (s *gormRecordStore) Get(ctx context.Context, name string) (*MigrationRecord, error) {
	var record MigrationRecord
	err := s.db.WithContext(ctx).Where("name = ?", name).First(&record).Error
	return &record, err
}

func (s *gormRecordStore) Delete(ctx context.Context, name string) error {
	return s.db.WithContext(ctx).Where("name = ?", name).Delete(&MigrationRecord{}).Error
}

func (s *gormRecordStore) Save(ctx context.Context, record *MigrationRecord) error {
	return s.db.WithContext(ctx).Create(record).Error
}

func (s *gormRecordStore) Clear(ctx context.Context) error {
	return s.db.WithContext(ctx).Exec("TRUNCATE TABLE migration_record").Error
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
	// 1. 初始化环境变量与数据源连接
	env, cleanup, err := r.initEnv(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	// 2. 初始化记录存储器
	store := NewGORMRecordStore(env.MySQLDst)

	// 3. 准备目标表结构与环境清理
	if err = r.prepareDatabase(ctx, store, env.MySQLDst); err != nil {
		return err
	}

	// 4. 执行迁移前预校验及数据清理
	if err = r.runPreHooks(ctx, env); err != nil {
		return err
	}

	// 5. 遍历并执行具体的迁移任务
	if err = r.runMigrators(ctx, env, store); err != nil {
		return err
	}

	// 5.5. 自动同步自增 ID 计数器起点
	if !r.cfg.DryRun && !r.cfg.SkipResetAutoIncrement {
		for _, m := range r.migrators {
			if syncer, ok := m.(IAutoIncrementSyncer); ok {
				if err = syncer.SyncAutoIncrement(ctx, env); err != nil {
					return err
				}
			}
		}
	}

	// 6. 执行迁移后修复钩子
	return r.runPostHooks(ctx, env)
}

// initEnv 集中建立源端及目标端连接并进行探活，返回清理资源的闭包和统一的环境对象
func (r *Runner) initEnv(ctx context.Context) (MigrationEnv, func(), error) {
	var cleanups []func()
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	mongoClient, err := mongo.Connect(options.Client().ApplyURI(r.cfg.MongoDSN))
	if err != nil {
		return MigrationEnv{}, cleanup, fmt.Errorf("连接源端 MongoDB 失败: %w", err)
	}
	cleanups = append(cleanups, func() {
		if err := mongoClient.Disconnect(context.Background()); err != nil {
			log.Printf("warning: 关闭 MongoDB 连接失败: %v", err)
		}
	})

	if err = mongoClient.Ping(ctx, readpref.Primary()); err != nil {
		cleanup()
		return MigrationEnv{}, nil, fmt.Errorf("探测源端 MongoDB 失败: %w", err)
	}

	var mysqlSRC *gorm.DB
	if r.cfg.MySQLSrcDSN != "" {
		mysqlSRC, err = openMySQL(r.cfg.MySQLSrcDSN)
		if err != nil {
			cleanup()
			return MigrationEnv{}, nil, fmt.Errorf("连接源端 MySQL 失败: %w", err)
		}
		cleanups = append(cleanups, func() {
			closeMySQL("源端 MySQL", mysqlSRC)
		})

		if err = pingMySQL(ctx, mysqlSRC); err != nil {
			cleanup()
			return MigrationEnv{}, nil, fmt.Errorf("探测源端 MySQL 失败: %w", err)
		}
	}

	mysqlDST, err := openMySQL(r.cfg.MySQLDstDSN)
	if err != nil {
		cleanup()
		return MigrationEnv{}, nil, fmt.Errorf("连接目标端 MySQL 失败: %w", err)
	}
	cleanups = append(cleanups, func() {
		closeMySQL("目标端 MySQL", mysqlDST)
	})

	if err = pingMySQL(ctx, mysqlDST); err != nil {
		cleanup()
		return MigrationEnv{}, nil, fmt.Errorf("探测目标端 MySQL 失败: %w", err)
	}

	env := MigrationEnv{
		MongoDB:         mongoClient.Database(r.cfg.MongoDBName),
		MySQLSrc:        mysqlSRC,
		MySQLDst:        mysqlDST,
		BatchSize:       r.cfg.BatchSize,
		DryRun:          r.cfg.DryRun,
		DefaultTenantID: r.defaultTenantID,
	}

	return env, cleanup, nil
}

// prepareDatabase 初始化迁移记录表和目标端表结构，并执行清空配置（若开启）
func (r *Runner) prepareDatabase(ctx context.Context, store IRecordStore, db *gorm.DB) error {
	if r.cfg.DryRun {
		return nil
	}

	// 始终自动初始化迁移状态控制记录表
	if err := store.AutoMigrate(ctx); err != nil {
		return fmt.Errorf("初始化迁移记录表失败: %w", err)
	}

	// 初始化目标端表结构
	if r.cfg.AutoMigrate && r.autoMigrateFunc != nil {
		log.Println("正在初始化目标端表结构")
		if err := r.autoMigrateFunc(db); err != nil {
			return fmt.Errorf("初始化目标端表结构失败: %w", err)
		}
	}

	// 清空目标表
	if r.cfg.Truncate {
		if err := r.truncateDestinations(ctx, db, store); err != nil {
			return err
		}
	}

	return nil
}

// runPreHooks 执行迁移前的冲突检测与数据清理钩子
func (r *Runner) runPreHooks(ctx context.Context, env MigrationEnv) error {
	for _, hook := range r.preHooks {
		if err := hook(ctx, env); err != nil {
			return fmt.Errorf("迁移前钩子失败: %w", err)
		}
	}
	return nil
}

// runPostHooks 执行迁移后的数据一致性修复钩子
func (r *Runner) runPostHooks(ctx context.Context, env MigrationEnv) error {
	for _, hook := range r.postHooks {
		if err := hook(ctx, env); err != nil {
			return fmt.Errorf("迁移后钩子失败: %w", err)
		}
	}
	return nil
}

// runMigrators 循环运行所有已注册的迁移器
func (r *Runner) runMigrators(ctx context.Context, env MigrationEnv, store IRecordStore) error {
	log.Printf("开始迁移: batch_size=%d dry_run=%t", r.cfg.BatchSize, r.cfg.DryRun)

	for _, migrator := range r.migrators {
		// 检查该任务是否已成功执行，已执行则跳过
		skipped, err := r.shouldSkip(ctx, store, migrator)
		if err != nil {
			return err
		}
		if skipped {
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
			if err = store.Save(ctx, &newRecord); err != nil {
				return fmt.Errorf("保存迁移历史记录 [%s] 失败: %w", migrator.Name(), err)
			}
		}
	}
	return nil
}

// shouldSkip 判断指定任务是否已存在执行成功的历史，存在则跳过以达到幂等性
func (r *Runner) shouldSkip(ctx context.Context, store IRecordStore, migrator Migrator) (bool, error) {
	if r.cfg.DryRun {
		return false, nil
	}

	if r.cfg.Force {
		if err := store.Delete(ctx, migrator.Name()); err != nil {
			return false, fmt.Errorf("强制重新迁移时清理旧记录 [%s] 失败: %w", migrator.Name(), err)
		}
		return false, nil
	}

	record, err := store.Get(ctx, migrator.Name())
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

func (r *Runner) truncateDestinations(ctx context.Context, db *gorm.DB, store IRecordStore) error {
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
	if err := store.Clear(ctx); err != nil {
		log.Printf("warning: 清空迁移历史记录表失败: %v", err)
	}
	return nil
}

func quoteIdentifier(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

package gormx

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/Duke1616/eiam/pkg/ctxutil"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

const (
	// IGNORE_TENANT_KEY 用于标识是否跳过租户隔离校验的 Context Key / GORM Option Key
	IGNORE_TENANT_KEY = "gormx:ignore_tenant"
	// INJECTED_KEY 用于标识当前 GORM Statement 是否已注入过隔离条件，防重复嵌套
	INJECTED_KEY = "eiam:tenant_injected"
)

// SharedConfig 共享规则配置
type SharedConfig struct {
	IsShared     bool   // 是否为共享资源，允许跨租户或与系统租户共享
	IsPrivate    bool   // 是否为纯私有资源，强制隔离
	IsIgnore     bool   // 是否为忽略模型，免除多租户插件的一切拦截
	Condition    string // 共享的附加 SQL 条件过滤表达式
	ConditionSQL string // 预构建好的 SQL 查询子句，避免运行时动态拼接
}

// TenantPlugin 提供多租户自动隔离的核心插件
type TenantPlugin struct {
	tenantColumn   string   // 租户列名，默认为 tenant_id
	systemTenantID int64    // 系统根租户 ID，默认为 ctxutil.SystemTenantID (1)
	strictSQL      string   // 预先格式化的严格等于 SQL 表达式（例如 "tenant_id = ?"）
	cache          sync.Map // 存储模型配置的缓存，Key 为表名（string），Value 为 SharedConfig
}

// Option 定义插件配置函数
type Option func(*TenantPlugin)

// WithTenantColumn 设置自定义的租户列名
func WithTenantColumn(col string) Option {
	return func(p *TenantPlugin) {
		p.tenantColumn = col
	}
}

// WithSystemTenantID 设置自定义的系统根租户 ID (上帝视角)
func WithSystemTenantID(id int64) Option {
	return func(p *TenantPlugin) {
		p.systemTenantID = id
	}
}

// NewTenantPlugin 初始化多租户隔离插件
func NewTenantPlugin(opts ...Option) *TenantPlugin {
	p := &TenantPlugin{
		tenantColumn:   "tenant_id",
		systemTenantID: ctxutil.SystemTenantID,
	}
	for _, opt := range opts {
		opt(p)
	}
	p.strictSQL = fmt.Sprintf("%s = ?", p.tenantColumn)
	return p
}

// Name 返回插件的唯一名称标识
func (p *TenantPlugin) Name() string { return "tenant_plugin" }

// Initialize 注册 GORM 回调钩子，接管增删改查生命周期以织入租户边界
func (p *TenantPlugin) Initialize(db *gorm.DB) error {
	cb := db.Callback()

	_ = cb.Create().Before("gorm:create").Register("tenant:handle_create", p.handleCreate)
	_ = cb.Query().Before("gorm:query").Register("tenant:handle_query", p.handleQuery)
	_ = cb.Update().Before("gorm:update").Register("tenant:handle_update", p.handleStrict)
	_ = cb.Delete().Before("gorm:delete").Register("tenant:handle_delete", p.handleStrict)

	return nil
}

// handleCreate 自动填充实体或切片实体的租户 ID 字段，实现写屏障
func (p *TenantPlugin) handleCreate(db *gorm.DB) {
	if p.shouldSkip(db) {
		return
	}

	tid := ctxutil.GetTenantID(db.Statement.Context)
	if tid == 0 {
		return
	}

	field, ok := db.Statement.Schema.FieldsByDBName[p.tenantColumn]
	if !ok {
		return
	}

	rv := db.Statement.ReflectValue
	// 循环解开指针与接口包装，获取到底层真实的值类型
	for rv.Kind() == reflect.Ptr || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return
		}
		rv = rv.Elem()
	}

	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			p.setTenantField(db.Statement.Context, field, rv.Index(i), tid.Int64())
		}
	case reflect.Struct:
		p.setTenantField(db.Statement.Context, field, rv, tid.Int64())
	default:

	}
}

// setTenantField 反射设值安全边界
func (p *TenantPlugin) setTenantField(ctx context.Context, field *schema.Field, value reflect.Value, tid int64) {
	for value.Kind() == reflect.Ptr || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return
		}
		value = value.Elem()
	}

	if value.Kind() != reflect.Struct {
		return
	}

	if _, isZero := field.ValueOf(ctx, value); isZero {
		_ = field.Set(ctx, value, tid)
	}
}

// handleQuery 在查询生命周期织入智能多租户安全边界
func (p *TenantPlugin) handleQuery(db *gorm.DB) {
	if p.shouldSkip(db) {
		return
	}

	tid := ctxutil.GetTenantID(db.Statement.Context)
	// 如果无租户上下文 (tid == 0)，豁免隔离限制，支持后台事务/系统迁移任务全局检索
	if tid == 0 {
		return
	}

	// 防重复注入拦截，避免 GORM 内部重用 Statement 时产生重复的条件嵌套
	if _, ok := db.InstanceGet(INJECTED_KEY); ok {
		return
	}

	if _, ok := db.Statement.Schema.FieldsByDBName[p.tenantColumn]; !ok {
		return
	}

	conf := p.getSharedConfig(db.Statement.Schema)
	db.InstanceSet(INJECTED_KEY, true)

	// 1. 纯私有模式。任何身份（包括超级管理员）都强制硬隔离在当前上下文租户内
	if conf.IsPrivate {
		db.Where(p.strictSQL, tid.Int64())
		return
	}

	// 2. 共享模式。根据实体共享策略与上下文标记，智能织入数据访问边界
	if conf.IsShared {
		// 上下文若带有 PrivateOnly 强制隔离标记，即便存在 Shared 配置也仅查当前租户私有数据
		if ctxutil.IsPrivateOnly(db.Statement.Context) {
			db.Where(p.strictSQL, tid.Int64())
			return
		}
		p.injectQueryPolicy(db, tid.Int64(), conf)
		return
	}

	// 3. 常规普通资源模式（未声明任何标签）。
	// 超级管理员默认豁免隔离限制，全局放行上帝视角；普通业务租户执行严格单租户硬隔离。
	if tid.Int64() == p.systemTenantID {
		return
	}
	db.Where(p.strictSQL, tid.Int64())
}

// injectQueryPolicy 根据实体共享策略，动态织入数据访问边界
func (p *TenantPlugin) injectQueryPolicy(db *gorm.DB, currentTid int64, conf SharedConfig) {
	// 系统主空间角色隔离，防止超管查策略列表看到全量数据，在此处必须锁定在系统租户 ID 内
	if currentTid == p.systemTenantID {
		db.Where(p.strictSQL, p.systemTenantID)
		return
	}

	// 共享实体查询：支持条件共享或默认全量系统共享，使用预先构建好的 SQL 子句避免格式化分配
	db.Where(conf.ConditionSQL, currentTid, p.systemTenantID)
}

// handleStrict 更新与删除时，严格限定租户边界，防止纵向/横向越权操作
func (p *TenantPlugin) handleStrict(db *gorm.DB) {
	if p.shouldSkip(db) {
		return
	}

	tid := ctxutil.GetTenantID(db.Statement.Context)
	// 系统租户或无租户上下文豁免严格写校验，以支持后台全局事务或超管跨租户修改
	if tid == 0 || tid.Int64() == p.systemTenantID {
		return
	}

	if _, ok := db.Statement.Schema.FieldsByDBName[p.tenantColumn]; ok {
		db.Where(p.strictSQL, tid.Int64())
	}
}

// getSharedConfig 获取并缓存模型的共享规则，第一次解析时构建查询 SQL 以提升高频查询的拼接效率
func (p *TenantPlugin) getSharedConfig(sch *schema.Schema) SharedConfig {
	if val, ok := p.cache.Load(sch.Table); ok {
		return val.(SharedConfig)
	}

	conf := SharedConfig{}
	if field, ok := sch.FieldsByDBName[p.tenantColumn]; ok {
		conf = p.parseSharedConfig(field)
	}

	p.cache.Store(sch.Table, conf)
	return conf
}

// parseSharedConfig 从字段 Tag 中提取并解析共享规则配置，解释为什么这样设计：为了使外部结构化调用保持简洁，在此处统一收拢解析与预拼接工作
func (p *TenantPlugin) parseSharedConfig(field *schema.Field) SharedConfig {
	conf := SharedConfig{}

	// 提取并解析专属的 eiam 隔离标签
	eiamTag := field.Tag.Get("eiam")
	if eiamTag != "" {
		conf = p.parseEiamTag(eiamTag)
	}

	// 预先装配条件 SQL 查询子句，避免运行时高频解析字符串带来的 GC 压力
	conf.ConditionSQL = p.buildConditionSQL(conf)
	return conf
}

// buildConditionSQL 根据共享规则参数，预先组装对应的 SQL 条件过滤子句
func (p *TenantPlugin) buildConditionSQL(conf SharedConfig) string {
	if !conf.IsShared {
		return p.strictSQL
	}
	if conf.Condition != "" {
		return fmt.Sprintf("(%s = ?) OR (%s = ? AND %s)", p.tenantColumn, p.tenantColumn, conf.Condition)
	}
	return fmt.Sprintf("%s = ? OR %s = ?", p.tenantColumn, p.tenantColumn)
}

// parseEiamTag 解析 eiam 专属标签，支持 shared:condition, private 或 ignore 声明
func (p *TenantPlugin) parseEiamTag(tag string) SharedConfig {
	conf := SharedConfig{}
	parts := strings.SplitN(tag, ":", 2)
	switch parts[0] {
	case "ignore":
		conf.IsIgnore = true
	case "shared":
		conf.IsShared = true
		if len(parts) > 1 {
			conf.Condition = parts[1]
		}
	case "private":
		conf.IsPrivate = true
	}
	return conf
}

// shouldSkip 检查该 Statement 是否需要跳过隔离校验，同时支持 GORM Option 与 Context.Context 双重提权控制
func (p *TenantPlugin) shouldSkip(db *gorm.DB) bool {
	// 1. 检查 GORM Option (通过 GORM Scope 临时提权)
	if val, ok := db.Get(IGNORE_TENANT_KEY); ok && val.(bool) {
		return true
	}

	// 2. 检查 Context 上下文 (解耦底层操作，支持在上层 Service 跨层传递提权标记)
	if db.Statement.Context != nil {
		if val, ok := db.Statement.Context.Value(IGNORE_TENANT_KEY).(bool); ok && val {
			return true
		}
	}

	if db.Statement.Schema == nil {
		return true
	}

	// 如果实体标注了 eiam:"ignore" 标签，则多租户插件自动跳过对此表的一切处理
	conf := p.getSharedConfig(db.Statement.Schema)
	return conf.IsIgnore
}

// IgnoreTenant 获取 GORM 链式调用的 Option，用于临时提权，绕过数据多租户隔离
func IgnoreTenant() func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Set(IGNORE_TENANT_KEY, true)
	}
}

// IgnoreTenantContext 将跳过租户隔离标记注入 Context，允许业务服务层跨越 Repository 控制隔离级别
func IgnoreTenantContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, IGNORE_TENANT_KEY, true)
}

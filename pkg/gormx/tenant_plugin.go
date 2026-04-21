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
	tenantColumn = "tenant_id"
	ignretnt     = "gormx:ignore_tenant"
)

// SharedConfig 共享规则配置
type SharedConfig struct {
	IsShared  bool
	Condition string
}

// TenantPlugin 提供多租户自动隔离的核心插件
type TenantPlugin struct {
	// cache 用于存储模型配置的缓存，Key 为表名，Value 为 SharedConfig
	cache sync.Map
}

func NewTenantPlugin() *TenantPlugin {
	return &TenantPlugin{}
}

func (p *TenantPlugin) Name() string { return "tenant_plugin" }

// Initialize 统一注册 GORM 钩子
func (p *TenantPlugin) Initialize(db *gorm.DB) error {
	cb := db.Callback()

	_ = cb.Create().Before("gorm:create").Register("tenant:handle_create", p.handleCreate)
	_ = cb.Query().Before("gorm:query").Register("tenant:handle_query", p.handleQuery)
	_ = cb.Update().Before("gorm:update").Register("tenant:handle_update", p.handleStrict)
	_ = cb.Delete().Before("gorm:delete").Register("tenant:handle_delete", p.handleStrict)

	return nil
}

// handleCreate 插入时的租户 ID 自动填充
func (p *TenantPlugin) handleCreate(db *gorm.DB) {
	if p.shouldSkip(db) {
		return
	}

	tid := ctxutil.GetTenantID(db.Statement.Context)
	if tid == 0 {
		return
	}

	field, ok := db.Statement.Schema.FieldsByDBName[tenantColumn]
	if !ok {
		return
	}

	rv := db.Statement.ReflectValue
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			p.setTenantField(db.Statement.Context, field, rv.Index(i), tid.Int64())
		}
	case reflect.Struct:
		p.setTenantField(db.Statement.Context, field, rv, tid.Int64())
	case reflect.Ptr:
		p.setTenantField(db.Statement.Context, field, rv.Elem(), tid.Int64())
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

// handleQuery 查询时的智能租户隔离条件
func (p *TenantPlugin) handleQuery(db *gorm.DB) {
	if p.shouldSkip(db) {
		return
	}

	tid := ctxutil.GetTenantID(db.Statement.Context)
	if tid == 0 {
		return // 忽略无租户上下文的请求
	}

	if _, ok := db.Statement.Schema.FieldsByDBName[tenantColumn]; !ok {
		return // 该表无 tenant_id 字段，不作隔离
	}

	conf := p.getSharedConfig(db.Statement.Schema)
	p.injectQueryPolicy(db, tid.Int64(), conf)
}

// injectQueryPolicy 根据实体配置，动态织入数据访问边界
func (p *TenantPlugin) injectQueryPolicy(db *gorm.DB, currentTid int64, conf SharedConfig) {
	// 1. 普通隔离：表不支持共享，严格限制在当前租户内
	if !conf.IsShared {
		db.Where(fmt.Sprintf("%s = ?", tenantColumn), currentTid)
		return
	}

	// 2. 系统租户视角：系统租户管理自己的数据（跨租户管理通过 IgnoreTenant 提权）
	if currentTid == ctxutil.SystemTenantID {
		db.Where(fmt.Sprintf("%s = ?", tenantColumn), ctxutil.SystemTenantID)
		return
	}

	// 3. 租户视角视阈混合：自己的私有资产 + 系统的受限共享资产
	if conf.Condition != "" {
		db.Where(
			fmt.Sprintf("(%s = ?) OR (%s = ? AND %s)", tenantColumn, tenantColumn, conf.Condition),
			currentTid, ctxutil.SystemTenantID,
		)
	} else {
		db.Where(fmt.Sprintf("%s IN (?, ?)", tenantColumn), currentTid, ctxutil.SystemTenantID)
	}
}

// handleStrict 更新与删除时，严格限定租户边界 (防越权操作)
func (p *TenantPlugin) handleStrict(db *gorm.DB) {
	if p.shouldSkip(db) {
		return
	}

	tid := ctxutil.GetTenantID(db.Statement.Context)
	if tid == 0 {
		return
	}

	if _, ok := db.Statement.Schema.FieldsByDBName[tenantColumn]; ok {
		db.Where(fmt.Sprintf("%s = ?", tenantColumn), tid.Int64())
	}
}

// getSharedConfig 提取并缓存模型的共享规则
func (p *TenantPlugin) getSharedConfig(sch *schema.Schema) SharedConfig {
	if val, ok := p.cache.Load(sch.Table); ok {
		return val.(SharedConfig)
	}

	conf := SharedConfig{}
	if field, ok := sch.FieldsByDBName[tenantColumn]; ok {
		eiamTag := field.Tag.Get("eiam")
		if eiamTag != "" {
			conf = p.parseEiamTag(eiamTag)
		} else {
			conf = p.fallbackLegacyTag(field.Tag)
		}
	}

	p.cache.Store(sch.Table, conf)
	return conf
}

// parseEiamTag 解析优雅的顶层标识符 e.g. eiam:"shared:type=1"
func (p *TenantPlugin) parseEiamTag(tag string) SharedConfig {
	conf := SharedConfig{}
	parts := strings.SplitN(tag, ":", 2)
	if parts[0] == "shared" {
		conf.IsShared = true
		if len(parts) > 1 {
			conf.Condition = parts[1]
		}
	}
	return conf
}

// fallbackLegacyTag 向下兼容旧版的 gorm 内嵌注释 e.g. gorm:"...;eiam:'shared'"
func (p *TenantPlugin) fallbackLegacyTag(tag reflect.StructTag) SharedConfig {
	conf := SharedConfig{}
	tagStr := strings.ToLower(string(tag))
	if strings.Contains(tagStr, "eiam") && strings.Contains(tagStr, "shared") {
		conf.IsShared = true
	}
	return conf
}

// shouldSkip 资源守卫：校验是否越权或跳过拦截
func (p *TenantPlugin) shouldSkip(db *gorm.DB) bool {
	if val, ok := db.Get(ignretnt); ok && val.(bool) {
		return true
	}
	return db.Statement.Schema == nil
}

// IgnoreTenant 系统提权：跳过租户隔离
func IgnoreTenant() func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Set(ignretnt, true)
	}
}

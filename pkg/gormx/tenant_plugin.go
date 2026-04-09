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

// TenantPlugin 提供多租户自动隔离的核心插件
type TenantPlugin struct {
	// cache 用于存储模型是否共享的判定结果，Key 为表名，Value 为 bool
	cache sync.Map
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
			p.setTenantField(db.Statement.Context, field, rv.Index(i), tid)
		}
	case reflect.Struct:
		p.setTenantField(db.Statement.Context, field, rv, tid)
	case reflect.Ptr:
		p.setTenantField(db.Statement.Context, field, rv.Elem(), tid)
	}
}

// setTenantField 安全设置字段值
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

// handleQuery 查询时的租户条件
func (p *TenantPlugin) handleQuery(db *gorm.DB) {
	if p.shouldSkip(db) {
		return
	}

	tid := ctxutil.GetTenantID(db.Statement.Context)
	if tid != 0 {
		if _, ok := db.Statement.Schema.FieldsByDBName[tenantColumn]; ok {
			// 核心优化：利用插件内部缓存探测结果
			if p.isShared(db.Statement.Schema) {
				db.Where(fmt.Sprintf("%s IN (?, 0)", tenantColumn), tid)
			} else {
				db.Where(fmt.Sprintf("%s = ?", tenantColumn), tid)
			}
		}
	}
}

// isShared 探测该模型是否标记为 eiam:"shared"
func (p *TenantPlugin) isShared(sch *schema.Schema) bool {
	// 1. 尝试从缓存读取 (Key 使用表名，因为 Schema 是单例)
	if val, ok := p.cache.Load(sch.Table); ok {
		return val.(bool)
	}

	// 2. 缓存未命中，执行探测逻辑
	isShared := false
	if field, ok := sch.FieldsByDBName[tenantColumn]; ok {
		tag := string(field.Tag)
		if strings.Contains(tag, `eiam:"shared"`) || strings.Contains(tag, `eiam:'shared'`) {
			isShared = true
		}
	}

	// 3. 结果存入缓存
	p.cache.Store(sch.Table, isShared)
	return isShared
}

// handleStrict 更新/删除时的租户条件
func (p *TenantPlugin) handleStrict(db *gorm.DB) {
	if p.shouldSkip(db) {
		return
	}

	tid := ctxutil.GetTenantID(db.Statement.Context)
	if tid != 0 {
		if _, ok := db.Statement.Schema.FieldsByDBName[tenantColumn]; ok {
			db.Where(fmt.Sprintf("%s = ?", tenantColumn), tid)
		}
	}
}

// shouldSkip 卫语句
func (p *TenantPlugin) shouldSkip(db *gorm.DB) bool {
	if val, ok := db.Get(ignretnt); ok && val.(bool) {
		return true
	}
	return db.Statement.Schema == nil
}

// IgnoreTenant 跳过租户隔离
func IgnoreTenant() func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Set(ignretnt, true)
	}
}

func NewTenantPlugin() *TenantPlugin {
	return &TenantPlugin{}
}

package gormx

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/Duke1616/eiam/pkg/ctxutil"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

const (
	tenantColumn = "tenant_id"
	ignretnt     = "gormx:ignore_tenant"
)

// TenantPlugin 提供多租户自动隔离的核心插件
type TenantPlugin struct{}

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

	// 核心修复：处理批量插入场景 (ReflectValue 为 Slice)
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
	// 如果已经是指针/接口，递归取值
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

// handleQuery 查询时的租户条件：允许看到当前租户或系统全局（0号）租户
func (p *TenantPlugin) handleQuery(db *gorm.DB) {
	if p.shouldSkip(db) {
		return
	}

	tid := ctxutil.GetTenantID(db.Statement.Context)
	if tid != 0 {
		if field, ok := db.Statement.Schema.FieldsByDBName[tenantColumn]; ok {
			tag := string(field.Tag)
			if strings.Contains(tag, `eiam:"shared"`) || strings.Contains(tag, `eiam:'shared'`) {
				db.Where(fmt.Sprintf("%s IN (?, 0)", tenantColumn), tid)
			} else {
				db.Where(fmt.Sprintf("%s = ?", tenantColumn), tid)
			}
		}
	}
}

// handleStrict 更新/删除时的租户条件：严禁跨租户或篡改全局数据
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

package gormx

import (
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"gorm.io/gorm"
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
	// 定义核心拦截点：在所有物理操作执行前插入隔离逻辑
	cb := db.Callback()
	
	_ = cb.Create().Before("gorm:create").Register("tenant:handle_create", p.handleCreate)
	_ = cb.Query().Before("gorm:query").Register("tenant:handle_query", p.handleFilter)
	_ = cb.Update().Before("gorm:update").Register("tenant:handle_update", p.handleFilter)
	_ = cb.Delete().Before("gorm:delete").Register("tenant:handle_delete", p.handleFilter)
	
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

	// 利用 GORM 的字段探测机制，如果模型包含 tenant_id 且为空，则自动补充
	if field, ok := db.Statement.Schema.FieldsByDBName[tenantColumn]; ok {
		if _, isZero := field.ValueOf(db.Statement.Context, db.Statement.ReflectValue); isZero {
			_ = field.Set(db.Statement.Context, db.Statement.ReflectValue, tid)
		}
	}
}

// handleFilter 查询/更新/删除时的租户条件自动挂载 (核心隔离点)
func (p *TenantPlugin) handleFilter(db *gorm.DB) {
	if p.shouldSkip(db) {
		return
	}

	tid := ctxutil.GetTenantID(db.Statement.Context)
	if tid != 0 {
		// 只有当操作的 Schema 包含 tenant_id 列时才会自动注入 Where
		if _, ok := db.Statement.Schema.FieldsByDBName[tenantColumn]; ok {
			db.Where(tenantColumn+" = ?", tid)
		}
	}
}

// shouldSkip 卫语句：判断是否需要跳过插件逻辑
func (p *TenantPlugin) shouldSkip(db *gorm.DB) bool {
	// 1. 显式声明了 IgnoreTenant
	if val, ok := db.Get(ignretnt); ok && val.(bool) {
		return true
	}

	// 2. 原始 SQL 查询
	if db.Statement.Schema == nil {
		return true
	}

	return false
}

// IgnoreTenant 跳过租户隔离的作用域工具
func IgnoreTenant() func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Set(ignretnt, true)
	}
}

func NewTenantPlugin() *TenantPlugin {
	return &TenantPlugin{}
}

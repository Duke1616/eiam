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

	// 利用 GORM 的字段探测机制，如果模型包含 tenant_id 且为空，则自动补充
	if field, ok := db.Statement.Schema.FieldsByDBName[tenantColumn]; ok {
		if _, isZero := field.ValueOf(db.Statement.Context, db.Statement.ReflectValue); isZero {
			_ = field.Set(db.Statement.Context, db.Statement.ReflectValue, tid)
		}
	}
}

// handleQuery 查询时的租户条件：允许看到当前租户或系统全局（0号）租户
func (p *TenantPlugin) handleQuery(db *gorm.DB) {
	if p.shouldSkip(db) {
		return
	}

	tid := ctxutil.GetTenantID(db.Statement.Context)
	if tid != 0 {
		if _, ok := db.Statement.Schema.FieldsByDBName[tenantColumn]; ok {
			// NOTE: 在查询时，我们默认允许用户看到自己租户及 0 号全局租户的信息
			db.Where("(tenant_id = ? OR tenant_id = 0)", tid)
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
			// NOTE: 在更新/删除时，强制锁定为该租户私有空间，确保其不能通过权限变更或其他手段篡改全局 0 号资源
			db.Where("tenant_id = ?", tid)
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

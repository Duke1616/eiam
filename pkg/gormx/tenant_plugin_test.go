package gormx

import (
	"context"
	"testing"

	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestUser 普通私有实体，没有特殊 eiam 标签
type TestUser struct {
	ID       uint `gorm:"primaryKey"`
	Name     string
	TenantID int64 `gorm:"column:tenant_id"`
}

// TestSharedResource 显式声明为共享资产的实体
type TestSharedResource struct {
	ID       uint `gorm:"primaryKey"`
	Name     string
	TenantID int64 `gorm:"column:tenant_id" eiam:"shared"`
}

// TestPrivateResource 显式声明为强隔离私有资产的实体
type TestPrivateResource struct {
	ID       uint `gorm:"primaryKey"`
	Name     string
	TenantID int64 `gorm:"column:tenant_id" eiam:"private"`
}

// TestConditionResource 显式声明为带条件共享资产的实体
type TestConditionResource struct {
	ID       uint `gorm:"primaryKey"`
	Name     string
	Type     int
	TenantID int64 `gorm:"column:tenant_id" eiam:"shared:type=1"`
}

// tenantTestCase 统一的声明式多租户测试用例结构定义
type tenantTestCase struct {
	name       string
	tenantID   int64
	models     []any
	opts       []Option
	setupCtx   func(ctx context.Context) context.Context
	dbModifier func(db *gorm.DB) *gorm.DB
	before     func(t *testing.T, db *gorm.DB)
	run        func(t *testing.T, db *gorm.DB)
	after      func(t *testing.T, db *gorm.DB)
}

// setupTestDB 通用且干净的多模型隔离数据库初始化辅助函数
func setupTestDB(t *testing.T, models []any, opts ...Option) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	plugin := NewTenantPlugin(opts...)
	err = db.Use(plugin)
	require.NoError(t, err)

	if len(models) > 0 {
		err = db.AutoMigrate(models...)
		require.NoError(t, err)
	}
	return db
}

// runTenantTests 声明式测试套件运行核心（统一调度生命周期、上下文及环境装配）
func runTenantTests(t *testing.T, defaultModels []any, tests []tenantTestCase, defaultOpts ...Option) {
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// 智能继承：如用例无特殊声明，继承测试套件级别的默认 Model 及配置 Option
			models := tc.models
			if len(models) == 0 {
				models = defaultModels
			}
			opts := tc.opts
			if len(opts) == 0 {
				opts = defaultOpts
			}

			// 为每一个子测试用例提供干净隔离的数据库，拒绝脏数据残留
			db := setupTestDB(t, models, opts...)

			if tc.before != nil {
				tc.before(t, db)
			}

			ctx := context.Background()
			if tc.tenantID != 0 {
				ctx = ctxutil.WithTenantID(ctx, tc.tenantID)
			}
			if tc.setupCtx != nil {
				ctx = tc.setupCtx(ctx)
			}

			scopedDB := db.WithContext(ctx)
			if tc.dbModifier != nil {
				scopedDB = tc.dbModifier(scopedDB)
			}

			if tc.run != nil {
				tc.run(t, scopedDB)
			}

			if tc.after != nil {
				tc.after(t, db)
			}
		})
	}
}

// TestTenantPlugin_Create 单元测试：自动填充写入实体的 tenant_id 字段
func TestTenantPlugin_Create(t *testing.T) {
	defaultModels := []any{&TestUser{}}

	tests := []tenantTestCase{
		{
			name:     "单实体写入自动填充租户ID",
			tenantID: 100,
			run: func(t *testing.T, db *gorm.DB) {
				user := TestUser{Name: "Luan"}
				err := db.Create(&user).Error
				require.NoError(t, err)
				assert.Equal(t, int64(100), user.TenantID)
			},
			after: func(t *testing.T, db *gorm.DB) {
				var dbUser TestUser
				err := db.Session(&gorm.Session{}).First(&dbUser).Error
				require.NoError(t, err)
				assert.Equal(t, int64(100), dbUser.TenantID)
			},
		},
		{
			name:     "切片批量写入自动填充租户ID",
			tenantID: 200,
			run: func(t *testing.T, db *gorm.DB) {
				users := []TestUser{
					{Name: "User1"},
					{Name: "User2"},
				}
				err := db.Create(&users).Error
				require.NoError(t, err)
				assert.Equal(t, int64(200), users[0].TenantID)
				assert.Equal(t, int64(200), users[1].TenantID)
			},
		},
		{
			name:     "已显式指定租户ID时不覆盖",
			tenantID: 300,
			run: func(t *testing.T, db *gorm.DB) {
				user := TestUser{Name: "User3", TenantID: 999}
				err := db.Create(&user).Error
				require.NoError(t, err)
				assert.Equal(t, int64(999), user.TenantID)
			},
		},
	}

	runTenantTests(t, defaultModels, tests)
}

// TestTenantPlugin_Query 单元测试：验证在各类共享配置下的多租户智能隔离查询行为
func TestTenantPlugin_Query(t *testing.T) {
	defaultModels := []any{
		&TestUser{},
		&TestSharedResource{},
		&TestPrivateResource{},
		&TestConditionResource{},
	}

	// 统一的数据环境装载
	seedData := func(t *testing.T, db *gorm.DB) {
		require.NoError(t, db.Session(&gorm.Session{}).Create([]TestUser{
			{Name: "SysUser", TenantID: ctxutil.SystemTenantID},
			{Name: "TenantAUser", TenantID: 10},
			{Name: "TenantBUser", TenantID: 20},
		}).Error)

		require.NoError(t, db.Session(&gorm.Session{}).Create([]TestSharedResource{
			{Name: "SysShared", TenantID: ctxutil.SystemTenantID},
			{Name: "TenantAShared", TenantID: 10},
			{Name: "TenantBShared", TenantID: 20},
		}).Error)

		require.NoError(t, db.Session(&gorm.Session{}).Create([]TestPrivateResource{
			{Name: "SysPrivate", TenantID: ctxutil.SystemTenantID},
			{Name: "TenantAPrivate", TenantID: 10},
			{Name: "TenantBPrivate", TenantID: 20},
		}).Error)

		require.NoError(t, db.Session(&gorm.Session{}).Create([]TestConditionResource{
			{Name: "SysCondMatched", Type: 1, TenantID: ctxutil.SystemTenantID},
			{Name: "SysCondUnmatched", Type: 2, TenantID: ctxutil.SystemTenantID},
			{Name: "TenantACond", Type: 2, TenantID: 10},
		}).Error)
	}

	tests := []tenantTestCase{
		{
			name:     "普通私有实体_业务租户查询_严格数据水平隔离",
			tenantID: 10,
			before:   seedData,
			run: func(t *testing.T, db *gorm.DB) {
				var list []TestUser
				err := db.Find(&list).Error
				require.NoError(t, err)
				assert.Len(t, list, 1)
				assert.Equal(t, "TenantAUser", list[0].Name)
			},
		},
		{
			name:     "普通私有实体_超级系统管理员查询_上帝视角豁免隔离限制",
			tenantID: ctxutil.SystemTenantID,
			before:   seedData,
			run: func(t *testing.T, db *gorm.DB) {
				var list []TestUser
				err := db.Find(&list).Error
				require.NoError(t, err)
				assert.Len(t, list, 3)
			},
		},
		{
			name:     "私有强隔离实体_超级系统管理员查询_依旧执行严格硬隔离",
			tenantID: ctxutil.SystemTenantID,
			before:   seedData,
			run: func(t *testing.T, db *gorm.DB) {
				var list []TestPrivateResource
				err := db.Find(&list).Error
				require.NoError(t, err)
				assert.Len(t, list, 1)
				assert.Equal(t, "SysPrivate", list[0].Name)
			},
		},
		{
			name:     "共享资产实体_业务租户查询_可获取当前租户数据与超级管理员的系统共享数据",
			tenantID: 10,
			before:   seedData,
			run: func(t *testing.T, db *gorm.DB) {
				var list []TestSharedResource
				err := db.Find(&list).Error
				require.NoError(t, err)
				assert.Len(t, list, 2)
				names := []string{list[0].Name, list[1].Name}
				assert.Contains(t, names, "SysShared")
				assert.Contains(t, names, "TenantAShared")
			},
		},
		{
			name:     "带条件共享资产实体_业务租户查询_可获取当前租户数据与超管下满足条件的共享数据",
			tenantID: 10,
			before:   seedData,
			run: func(t *testing.T, db *gorm.DB) {
				var list []TestConditionResource
				err := db.Find(&list).Error
				require.NoError(t, err)
				assert.Len(t, list, 2)
				names := []string{list[0].Name, list[1].Name}
				assert.Contains(t, names, "SysCondMatched")
				assert.Contains(t, names, "TenantACond")
				assert.NotContains(t, names, "SysCondUnmatched")
			},
		},
		{
			name:     "共享资产实体_带有PrivateOnly上下文_强制关闭共享获取渠道",
			tenantID: 10,
			before:   seedData,
			setupCtx: func(ctx context.Context) context.Context {
				return ctxutil.WithPrivateOnly(ctx)
			},
			run: func(t *testing.T, db *gorm.DB) {
				var list []TestSharedResource
				err := db.Find(&list).Error
				require.NoError(t, err)
				assert.Len(t, list, 1)
				assert.Equal(t, "TenantAShared", list[0].Name)
			},
		},
		{
			name:     "系统级提权_GORM Scope_绕过隔离规则",
			tenantID: 10,
			before:   seedData,
			dbModifier: func(db *gorm.DB) *gorm.DB {
				return db.Scopes(IgnoreTenant())
			},
			run: func(t *testing.T, db *gorm.DB) {
				var list []TestUser
				err := db.Find(&list).Error
				require.NoError(t, err)
				assert.Len(t, list, 3)
			},
		},
		{
			name:     "系统级提权_Context Context_跨层提权绕过隔离",
			tenantID: 10,
			before:   seedData,
			setupCtx: func(ctx context.Context) context.Context {
				return IgnoreTenantContext(ctx)
			},
			run: func(t *testing.T, db *gorm.DB) {
				var list []TestUser
				err := db.Find(&list).Error
				require.NoError(t, err)
				assert.Len(t, list, 3)
			},
		},
	}

	runTenantTests(t, defaultModels, tests)
}

// TestTenantPlugin_WriteStrict 单元测试：防越权更新与删除校验
func TestTenantPlugin_WriteStrict(t *testing.T) {
	defaultModels := []any{&TestUser{}}

	// 统一的数据环境装配（采用完全确定的 Static ID 插入，彻底消除了跨闭包共享实体指针的全局脏味道）
	seedData := func(t *testing.T, db *gorm.DB) {
		require.NoError(t, db.Session(&gorm.Session{}).Create([]TestUser{
			{ID: 1, Name: "UserA", TenantID: 10},
			{ID: 2, Name: "UserB", TenantID: 20},
		}).Error)
	}

	tests := []tenantTestCase{
		{
			name:     "业务租户更新他人数据被严格隔离约束而失败",
			tenantID: 10,
			before:   seedData,
			run: func(t *testing.T, db *gorm.DB) {
				res := db.Model(&TestUser{}).Where("id = ?", 2).Update("name", "Hacked")
				require.NoError(t, res.Error)
				assert.Zero(t, res.RowsAffected)
			},
			after: func(t *testing.T, db *gorm.DB) {
				var dbUser TestUser
				err := db.Session(&gorm.Session{}).First(&dbUser, 2).Error
				require.NoError(t, err)
				assert.Equal(t, "UserB", dbUser.Name)
			},
		},
		{
			name:     "业务租户只能修改本租户空间内的数据",
			tenantID: 10,
			before:   seedData,
			run: func(t *testing.T, db *gorm.DB) {
				res := db.Model(&TestUser{}).Where("id = ?", 1).Update("name", "UpdatedA")
				require.NoError(t, res.Error)
				assert.Equal(t, int64(1), res.RowsAffected)
			},
			after: func(t *testing.T, db *gorm.DB) {
				var dbUser TestUser
				err := db.Session(&gorm.Session{}).First(&dbUser, 1).Error
				require.NoError(t, err)
				assert.Equal(t, "UpdatedA", dbUser.Name)
			},
		},
		{
			name:     "超级系统管理员免除写操作硬限制",
			tenantID: ctxutil.SystemTenantID,
			before:   seedData,
			run: func(t *testing.T, db *gorm.DB) {
				res := db.Model(&TestUser{}).Where("id = ?", 2).Update("name", "SysUpdatedB")
				require.NoError(t, res.Error)
				assert.Equal(t, int64(1), res.RowsAffected)
			},
			after: func(t *testing.T, db *gorm.DB) {
				var dbUser TestUser
				err := db.Session(&gorm.Session{}).First(&dbUser, 2).Error
				require.NoError(t, err)
				assert.Equal(t, "SysUpdatedB", dbUser.Name)
			},
		},
	}

	runTenantTests(t, defaultModels, tests)
}

// TestTenantPlugin_CustomOptions 单元测试：自定义配置验证
func TestTenantPlugin_CustomOptions(t *testing.T) {
	type CustomEntity struct {
		ID             uint `gorm:"primaryKey"`
		Name           string
		CustomTenantID int64 `gorm:"column:custom_tenant_id"`
	}

	defaultModels := []any{&CustomEntity{}}

	seedData := func(t *testing.T, db *gorm.DB) {
		require.NoError(t, db.Session(&gorm.Session{}).Create([]CustomEntity{
			{Name: "SysData", CustomTenantID: 999},
			{Name: "TenantAData", CustomTenantID: 100},
		}).Error)
	}

	tests := []tenantTestCase{
		{
			name:     "自定义租户字段写入自动填充验证",
			tenantID: 100,
			run: func(t *testing.T, db *gorm.DB) {
				entity := CustomEntity{Name: "TenantADataNew"}
				err := db.Create(&entity).Error
				require.NoError(t, err)
				assert.Equal(t, int64(100), entity.CustomTenantID)
			},
		},
		{
			name:     "自定义系统租户上帝视角免隔离验证",
			tenantID: 999,
			before:   seedData,
			run: func(t *testing.T, db *gorm.DB) {
				var list []CustomEntity
				err := db.Find(&list).Error
				require.NoError(t, err)
				assert.Len(t, list, 2)
				var names []string
				for _, e := range list {
					names = append(names, e.Name)
				}
				assert.Contains(t, names, "SysData")
				assert.Contains(t, names, "TenantAData")
			},
		},
		{
			name:     "自定义普通业务租户正常水平隔离验证",
			tenantID: 100,
			before:   seedData,
			run: func(t *testing.T, db *gorm.DB) {
				var list []CustomEntity
				err := db.Find(&list).Error
				require.NoError(t, err)
				assert.Len(t, list, 1)
				assert.Equal(t, int64(100), list[0].CustomTenantID)
				assert.Equal(t, "TenantAData", list[0].Name)
			},
		},
	}

	// 统一调度自定义模型测试，传入自定义 Model 列名和自定义系统超管 ID 选项
	runTenantTests(t, defaultModels, tests,
		WithTenantColumn("custom_tenant_id"),
		WithSystemTenantID(999),
	)
}

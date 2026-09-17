package dao

import (
	"context"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/gormx"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

func setupTestDB(t *testing.T) (*gorm.DB, IPolicyDAO) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
	})
	require.NoError(t, err)

	require.NoError(t, db.Use(gormx.NewTenantPlugin()))
	require.NoError(t, db.AutoMigrate(&Policy{}, &PolicyAssignment{}))

	return db, NewPolicyDAO(db)
}

func TestGetAttachedPoliciesWithFilter_TenantContext(t *testing.T) {
	db, dao := setupTestDB(t)

	ctx := ctxutil.WithTenantID(context.Background(), 3)

	// 插入租户3的策略与分配关系
	err := db.WithContext(ctx).Create(&Policy{
		TenantId: 3,
		Code:     "policy_test_1",
		Name:     "测试策略1",
		Document: sqlx.JSONColumn[[]domain.Statement]{
			Val:   []domain.Statement{},
			Valid: true,
		},
	}).Error
	require.NoError(t, err)

	err = db.WithContext(ctx).Create(&PolicyAssignment{
		TenantId:   3,
		SubType:    "user",
		SubCode:    "admin",
		PolicyCode: "policy_test_1",
		Ctime:      1700000000,
	}).Error
	require.NoError(t, err)

	// 测试查询
	policies, total, err := dao.GetAttachedPoliciesWithFilter(ctx, "user", "admin", 0, 10, "", 0)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, policies, 1)
	assert.Equal(t, "policy_test_1", policies[0].Code)
}

func TestListAssignments_WithPolicyTypeSubQuery(t *testing.T) {
	db, dao := setupTestDB(t)

	ctx := ctxutil.WithTenantID(context.Background(), 3)

	err := db.WithContext(ctx).Create(&Policy{
		TenantId: 3,
		Code:     "policy_custom_1",
		Name:     "自定义策略",
		Type:     2,
		Document: sqlx.JSONColumn[[]domain.Statement]{
			Val:   []domain.Statement{},
			Valid: true,
		},
	}).Error
	require.NoError(t, err)

	err = db.WithContext(ctx).Create(&PolicyAssignment{
		TenantId:   3,
		SubType:    "user",
		SubCode:    "alice",
		PolicyCode: "policy_custom_1",
		Ctime:      1700000000,
	}).Error
	require.NoError(t, err)

	// 按 policyType = 2 过滤
	assignments, total, err := dao.ListAssignments(ctx, 0, 10, "user", "", 2)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, assignments, 1)
	assert.Equal(t, "policy_custom_1", assignments[0].PolicyCode)
}

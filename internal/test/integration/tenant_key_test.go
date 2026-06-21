package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/service/tenant"
	testioc "github.com/Duke1616/eiam/internal/test/ioc"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type TenantKeySuite struct {
	suite.Suite
	db        *gorm.DB
	tenantSvc tenant.ITenantService
	keySvc    tenant.ITenantKeyService
}

func (s *TenantKeySuite) SetupSuite() {
	dir, _ := os.Getwd()
	viper.SetConfigFile(filepath.Join(dir, "../config/config.yaml"))
	_ = viper.ReadInConfig()

	deps, _ := testioc.InitPermissionSuiteDeps()
	s.db = deps.DB
	s.tenantSvc = deps.TenantSvc
	s.keySvc = deps.TenantKeySvc
}

func (s *TenantKeySuite) TearDownTest() {
	s.clearAll()
}

func (s *TenantKeySuite) clearAll() {
	s.db.Exec("DELETE FROM `tenant`")
	s.db.Exec("DELETE FROM `membership`")
	s.db.Exec("DELETE FROM `tenant_key`")
}

func (s *TenantKeySuite) TestTenantKey_Lifecycle() {
	ctx := context.Background()

	// 1. 创建租户并验证是否自动生成了 API Key
	tenantID, err := s.tenantSvc.CreateTenant(ctx, "测试租户", "test-tenant", "owner_user", 1001)
	s.NoError(err)
	s.True(tenantID > 0)

	// 2. 列表查询凭证，断言包含刚才生成的 Key
	keys, err := s.keySvc.ListKeysByTenantID(ctx, tenantID)
	s.NoError(err)
	s.Len(keys, 1)

	key := keys[0]
	s.Equal(tenantID, key.TenantID)
	s.True(strings.HasPrefix(key.AccessKey, "AK"))
	s.Len(key.AccessKey, 26) // "AK" (2字节) + 24字节十六进制 = 26 长度
	s.Len(key.SecretKey, 48) // 48字节十六进制
	s.Equal(1, key.Status)   // 默认是启用状态

	// 3. 校验能够通过 AccessKey 正确解析出 TenantID
	tid, err := s.keySvc.GetTenantIDByAccessKey(ctx, key.AccessKey)
	s.NoError(err)
	s.Equal(tenantID, tid)

	// 4. 校验 VerifyKey 方法
	// 4.1 正确的凭证
	verifiedTid, err := s.keySvc.VerifyKey(ctx, key.AccessKey, key.SecretKey)
	s.NoError(err)
	s.Equal(tenantID, verifiedTid)

	// 4.2 错误的 SecretKey
	_, err = s.keySvc.VerifyKey(ctx, key.AccessKey, "wrong_secret")
	s.ErrorIs(err, errs.ErrInvalidTenantKey)

	// 5. 将该 Key 禁用，验证是否无法再解析出 TenantID
	err = s.keySvc.UpdateKeyStatus(ctx, key.ID, 0)
	s.NoError(err)

	_, err = s.keySvc.GetTenantIDByAccessKey(ctx, key.AccessKey)
	s.ErrorIs(err, errs.ErrTenantKeyDisabled)

	// 5.1 禁用的凭证进行 VerifyKey
	_, err = s.keySvc.VerifyKey(ctx, key.AccessKey, key.SecretKey)
	s.ErrorIs(err, errs.ErrTenantKeyDisabled)
}

func (s *TenantKeySuite) TestInitPersonalTenant_Lifecycle() {
	ctx := context.Background()

	// 1. 初始化个人空间并验证是否生成了凭证
	tenantID, err := s.tenantSvc.InitPersonalTenant(ctx, 1002, "personal_user")
	s.NoError(err)
	s.True(tenantID > 0)

	keys, err := s.keySvc.ListKeysByTenantID(ctx, tenantID)
	s.NoError(err)
	s.Len(keys, 1)

	key := keys[0]
	s.Equal(tenantID, key.TenantID)
	s.True(strings.HasPrefix(key.AccessKey, "AK"))
	s.Equal(1, key.Status)
}

func TestTenantKey(t *testing.T) {
	suite.Run(t, new(TenantKeySuite))
}

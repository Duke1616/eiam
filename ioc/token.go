package ioc

import (
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/dao"
	tenantsvc "github.com/Duke1616/eiam/internal/service/tenant"
)

// InitTenantKeyService 为 token CLI 命令提供最小依赖注入：
// 只初始化 TenantKey + Service 两条 DAO/Repo 链，不启动完整 App。
func InitTenantKeyService() tenantsvc.ITenantKeyService {
	db := InitDBWithoutMigrate()

	tkDAO := dao.NewTenantKeyDAO(db)
	tkRepo := repository.NewTenantKeyRepository(tkDAO)

	svcDAO := dao.NewServiceDAO(db)
	svcRepo := repository.NewServiceRepository(svcDAO)

	return tenantsvc.NewTenantKeyService(tkRepo, svcRepo)
}

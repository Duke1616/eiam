package testioc

import (
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/policy"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/internal/service/tenant"
	"github.com/casbin/casbin/v2"
	"gorm.io/gorm"
)

type PermissionSuiteDeps struct {
	DB          *gorm.DB
	Enforcer    *casbin.SyncedEnforcer
	TenantSvc   tenant.ITenantService
	RoleSvc     role.IRoleService
	PolicySvc   policy.IPolicyService
	ResourceSvc resource.IResourceService
	PermSvc     permission.IPermissionService
}

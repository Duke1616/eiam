package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/internal/service/department"
	"github.com/Duke1616/eiam/internal/service/group"
	"github.com/Duke1616/eiam/internal/service/permission"
	policysvc "github.com/Duke1616/eiam/internal/service/policy"
	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/internal/service/tenant"
	testioc "github.com/Duke1616/eiam/internal/test/ioc"
	"github.com/Duke1616/eiam/ioc"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/casbin/casbin/v2"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type DeptGroupSuite struct {
	suite.Suite

	db       *gorm.DB
	enforcer *casbin.SyncedEnforcer

	tenantSvc   tenant.ITenantService
	roleSvc     role.IRoleService
	policySvc   policysvc.IPolicyService
	resourceSvc resource.IResourceService
	permSvc     permission.IPermissionService

	userRepo  repository.IUserRepository
	deptSvc   department.IDepartmentService
	groupSvc  group.IGroupService
}

func (s *DeptGroupSuite) SetupSuite() {
	dir, _ := os.Getwd()
	viper.SetConfigFile(filepath.Join(dir, "../config/config.yaml"))
	_ = viper.ReadInConfig()

	deps, _ := testioc.InitPermissionSuiteDeps()
	s.db = deps.DB
	s.enforcer = deps.Enforcer
	s.tenantSvc = deps.TenantSvc
	s.roleSvc = deps.RoleSvc
	s.policySvc = deps.PolicySvc
	s.resourceSvc = deps.ResourceSvc
	s.permSvc = deps.PermSvc

	// 手动装填 Department 与 Group Service
	redisClient := ioc.InitRedis()
	userCache := cache.NewUserCache(redisClient)
	tenantDAO := dao.NewTenantDAO(s.db)
	userDAO := dao.NewUserDAO(s.db)
	s.userRepo = repository.NewUserRepository(userDAO, tenantDAO, userCache)

	deptDAO := dao.NewDepartmentDAO(s.db)
	deptRepo := repository.NewDepartmentRepository(deptDAO, s.userRepo)
	s.deptSvc = department.NewDepartmentService(deptRepo)

	groupDAO := dao.NewGroupDAO(s.db)
	groupRepo := repository.NewGroupRepository(groupDAO, s.userRepo)
	s.groupSvc = group.NewGroupService(groupRepo, s.userRepo, s.enforcer)
}

func (s *DeptGroupSuite) TearDownTest() {
	s.clearAll()
}

func (s *DeptGroupSuite) clearAll() {
	s.db.Exec("DELETE FROM `tenant`")
	s.db.Exec("DELETE FROM `membership`")
	s.db.Exec("DELETE FROM `role`")
	s.db.Exec("DELETE FROM `policy`")
	s.db.Exec("DELETE FROM `policy_assignment`")
	s.db.Exec("DELETE FROM `api`")
	s.db.Exec("DELETE FROM `permission`")
	s.db.Exec("DELETE FROM `permission_binding`")
	s.db.Exec("DELETE FROM `casbin_rule`")
	s.db.Exec("DELETE FROM `menu`")
	s.db.Exec("DELETE FROM `department`")
	s.db.Exec("DELETE FROM `user_department`")
	s.db.Exec("DELETE FROM `group`")
	s.db.Exec("DELETE FROM `user_group`")
	s.db.Exec("DELETE FROM `user`")
	s.db.Exec("DELETE FROM `user_profile`")
}

// TestDepartment_CRUD 测试部门的基本操作与树状及级联删除校验
func (s *DeptGroupSuite) TestDepartment_CRUD() {
	ctx := ctxutil.WithTenantID(context.Background(), 2)

	// 1. 创建部门
	d1ID, err := s.deptSvc.Create(ctx, domain.Department{Name: "研发部", Sort: 1})
	s.NoError(err)
	s.True(d1ID > 0)

	d2ID, err := s.deptSvc.Create(ctx, domain.Department{ParentID: d1ID, Name: "架构组", Sort: 2, Leaders: []string{"leader1", "leader2"}, MainLeader: "leader1"})
	s.NoError(err)
	s.True(d2ID > 0)

	// 2. 获取部门详情
	dept, err := s.deptSvc.GetByID(ctx, d2ID)
	s.NoError(err)
	s.Equal("架构组", dept.Name)
	s.Equal(d1ID, dept.ParentID)
	s.Equal([]string{"leader1", "leader2"}, dept.Leaders)
	s.Equal("leader1", dept.MainLeader)

	// 3. 更新部门
	dept.Name = "架构与平台组"
	dept.Leaders = []string{"leader1", "leader3"}
	dept.MainLeader = "leader3"
	err = s.deptSvc.Update(ctx, dept)
	s.NoError(err)

	deptUpdated, err := s.deptSvc.GetByID(ctx, d2ID)
	s.NoError(err)
	s.Equal("架构与平台组", deptUpdated.Name)
	s.Equal([]string{"leader1", "leader3"}, deptUpdated.Leaders)
	s.Equal("leader3", deptUpdated.MainLeader)

	// 4. 获取部门树
	tree, err := s.deptSvc.List(ctx)
	s.NoError(err)
	s.Len(tree, 1)
	s.Equal("研发部", tree[0].Name)
	s.Len(tree[0].Children, 1)
	s.Equal("架构与平台组", tree[0].Children[0].Name)

	// 5. 校验级联删除：不能删除含有子部门的部门
	err = s.deptSvc.Delete(ctx, d1ID)
	s.Equal(department.ErrDeleteDeptWithChildren, err)

	// 6. 添加部门成员
	uID, err := s.userRepo.Create(ctx, domain.User{Username: "test_dept_user"})
	s.NoError(err)

	err = s.deptSvc.AssignUsers(ctx, d2ID, []int64{uID})
	s.NoError(err)

	// 7. 校验级联删除：不能删除含有成员的部门
	err = s.deptSvc.Delete(ctx, d2ID)
	s.Equal(department.ErrDeleteDeptWithMembers, err)

	// 8. 移除成员并删除
	err = s.deptSvc.RemoveUsers(ctx, d2ID, []int64{uID})
	s.NoError(err)

	err = s.deptSvc.Delete(ctx, d2ID)
	s.NoError(err)

	err = s.deptSvc.Delete(ctx, d1ID)
	s.NoError(err)
}

// TestGroup_CasbinInheritance 测试用户组通过 Casbin 隐式继承角色的授权流程
func (s *DeptGroupSuite) TestGroup_CasbinInheritance() {
	ctx := context.Background()
	// 创建租户 B (tid=3)
	tid, err := s.tenantSvc.CreateTenant(ctx, "租户B", "t-b", "admin_b", 3)
	s.NoError(err)
	tCtx := ctxutil.WithTenantID(ctx, tid)

	// 1. 准备私有资源 API
	api := domain.API{Service: "svc", Method: "POST", Path: "/data/edit"}
	_, err = s.resourceSvc.CreateAPI(tCtx, api)
	s.NoError(err)

	// 2. 准备权限项并绑定 API
	pid, err := s.permSvc.CreatePermission(tCtx, domain.Permission{Code: "perm:data:write"})
	s.NoError(err)
	err = s.permSvc.BindResourcesToPermission(tCtx, pid, "perm:data:write", []string{api.URN()})
	s.NoError(err)

	// 3. 创建自定义角色，把系统读写策略分配给该角色
	_, err = s.roleSvc.Create(tCtx, domain.Role{Code: "data_writer"})
	s.NoError(err)

	_, err = s.policySvc.CreatePolicy(tCtx, domain.Policy{
		Code: "policy_data_write",
		Type: domain.CustomPolicy,
		Statement: []domain.Statement{
			{Effect: domain.Allow, Action: []string{"perm:data:write"}, Resource: []string{"*"}},
		},
	})
	s.NoError(err)

	err = s.permSvc.AssignPolicyToRole(tCtx, "data_writer", "policy_data_write")
	s.NoError(err)

	// 4. 创建用户组
	groupID, err := s.groupSvc.Create(tCtx, domain.Group{
		Name: "研发组",
		Code: "rd_group",
		Desc: "研发团队用户组",
	})
	s.NoError(err)
	s.True(groupID > 0)

	// 5. 授权角色给用户组
	ok, err := s.groupSvc.AssignRole(tCtx, "rd_group", "data_writer")
	s.NoError(err)
	s.True(ok)

	// 6. 创建用户并加入用户组
	uID, err := s.userRepo.Create(tCtx, domain.User{Username: "rd_engineer"})
	s.NoError(err)
	s.True(uID > 0)

	ok, err = s.groupSvc.AssignMembers(tCtx, "rd_group", []string{"rd_engineer"})
	s.NoError(err)
	s.True(ok)

	// 7. 校验权限：该用户虽然没有被直接授权该角色，但因属于该组，应继承该角色从而获准访问
	allowed, err := s.permSvc.CheckAPI(tCtx, "rd_engineer", "svc", "POST", "/data/edit")
	s.NoError(err)
	s.True(allowed, "应当通过用户组隐式继承角色，被允许访问接口")

	// 8. 将用户移出用户组，再次校验应被拒绝
	ok, err = s.groupSvc.RemoveMembers(tCtx, "rd_group", []string{"rd_engineer"})
	s.NoError(err)
	s.True(ok)

	allowed, err = s.permSvc.CheckAPI(tCtx, "rd_engineer", "svc", "POST", "/data/edit")
	s.NoError(err)
	s.False(allowed, "移出用户组后，用户不应再具有该组分配的角色权限")
}

func TestDeptGroup(t *testing.T) {
	suite.Run(t, new(DeptGroupSuite))
}

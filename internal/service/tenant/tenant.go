package tenant

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/pkg/ctxutil"
)

// ITenantService 租户业务接口
//
//go:generate mockgen -source=./tenant.go -package=tenantmocks -destination=./mocks/tenant.mock.go -typed ITenantService
type ITenantService interface {
	// CreateTenant 创建一个租户空间
	CreateTenant(ctx context.Context, name, code string, ownerId int64) (int64, error)
	// InitPersonalTenant 为新用户初始化个人空间 (注册即拥有)
	InitPersonalTenant(ctx context.Context, userId int64, username string) (int64, error)
	// GetTenantsByUserId 查看用户属于哪些空间 (用于登录后选定或切换)
	GetTenantsByUserId(ctx context.Context, userId int64) ([]domain.Tenant, error)
	// CheckUserTenantAccess 校验用户是否有权进入该租户空间
	CheckUserTenantAccess(ctx context.Context, userId, tenantId int64) (bool, error)
}

type tenantService struct {
	repo    repository.ITenantRepository
	permSvc permission.IPermissionService // 注入权限服务：从此权力归 Casbin
	roleSvc role.IRoleService             // 注入角色服务：用于初始化系统固有角色
}

func NewTenantService(r repository.ITenantRepository, permSvc permission.IPermissionService, roleSvc role.IRoleService) ITenantService {
	return &tenantService{
		repo:    r,
		permSvc: permSvc,
		roleSvc: roleSvc,
	}
}

// CreateTenant 创建租户的核心流程
func (s *tenantService) CreateTenant(ctx context.Context, name, code string, ownerId int64) (int64, error) {
	// 1. 保存租户基本信息
	tenantID, err := s.repo.Create(ctx, domain.Tenant{
		Name:   name,
		Code:   code,
		Status: 1,
	})
	if err != nil {
		return 0, err
	}

	// 2. 将创建者加入该租户 (建立纯净契约关系)
	// 注意：此处 AddMembership 仅代表“入驻”，不承载授权信息
	err = s.repo.AddMembership(ctx, ownerId, tenantID)
	if err != nil {
		return 0, err
	}

	// 3. 在该租户下初始化系统内置最高权限角色
	ctxWithTenant := ctxutil.WithTenantID(ctx, tenantID)
	_, err = s.roleSvc.Create(ctxWithTenant, domain.Role{
		Name:   "超级管理员",
		Code:   "OWNER",
		Desc:   "系统内置最高权限拥有者",
		Status: true,
	})
	if err != nil {
		return 0, err
	}

	// 4. 通过 Casbin 分配 OWNER 角色 (宣示主权)
	// 真正的权力被存储在 Casbin 的 g 规则中。
	_, err = s.permSvc.AssignRoleToUser(ctxWithTenant, ownerId, "OWNER")

	return tenantID, err
}

func (s *tenantService) InitPersonalTenant(ctx context.Context, userId int64, username string) (int64, error) {
	// 初始化个人空间：同样适用这种“关系+授权”分离模式
	tenantID, err := s.repo.Create(ctx, domain.Tenant{
		Name:   username + "的个人空间",
		Code:   username + "-personal",
		Status: 1,
	})
	if err != nil {
		return 0, err
	}

	// 建立契约
	err = s.repo.AddMembership(ctx, userId, tenantID)
	if err != nil {
		return 0, err
	}

	// 初始化内置最高角色
	ctxWithTenant := ctxutil.WithTenantID(ctx, tenantID)
	_, err = s.roleSvc.Create(ctxWithTenant, domain.Role{
		Name:   "超级管理员",
		Code:   "OWNER",
		Desc:   "系统内置最高权限拥有者",
		Status: true,
	})
	if err != nil {
		return 0, err
	}

	// 分配 OWNER 角色
	_, err = s.permSvc.AssignRoleToUser(ctxWithTenant, userId, "OWNER")

	return tenantID, err
}

func (s *tenantService) GetTenantsByUserId(ctx context.Context, userId int64) ([]domain.Tenant, error) {
	return s.repo.FindTenantsByUserId(ctx, userId)
}

func (s *tenantService) CheckUserTenantAccess(ctx context.Context, userId, tenantId int64) (bool, error) {
	// 维持原状：契约存在即代表有权进入 (Context 入场券)
	_, err := s.repo.GetMembership(ctx, tenantId, userId)
	if err != nil {
		return false, nil
	}
	return true, nil
}

package tenant

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/role"
)

// ITenantService 租户业务接口
//
//go:generate mockgen -source=./tenant.go -package=tenantmocks -destination=./mocks/tenant.mock.go -typed ITenantService
type ITenantService interface {
	// CreateTenant 创建一个租户空间
	CreateTenant(ctx context.Context, name, code, username string, userID int64) (int64, error)
	// InitPersonalTenant 为新用户初始化个人空间 (注册即拥有)
	InitPersonalTenant(ctx context.Context, userId int64, username string) (int64, error)
	// GetTenantsByUserId 查看用户属于哪些空间 (用于登录后选定或切换)
	GetTenantsByUserId(ctx context.Context, userId int64) ([]domain.Tenant, error)
	// CheckUserTenantAccess 校验用户是否有权进入该租户空间
	CheckUserTenantAccess(ctx context.Context, userId, tenantId int64) (bool, error)
	// List 分页查看所有租户列表
	List(ctx context.Context, offset, limit int64) ([]domain.Tenant, int64, error)
	// Update 更新租户基本信息
	Update(ctx context.Context, t domain.Tenant) error
	// Delete 删除租户 (通常为逻辑删除)
	Delete(ctx context.Context, id int64) error
	// GetByID 获取租户详情
	GetByID(ctx context.Context, id int64) (domain.Tenant, error)
}

type tenantService struct {
	repo    repository.ITenantRepository
	roleSvc role.IRoleService // 注入角色服务：用于初始化系统固有角色
}

func NewTenantService(r repository.ITenantRepository, roleSvc role.IRoleService) ITenantService {
	return &tenantService{
		repo:    r,
		roleSvc: roleSvc,
	}
}

// CreateTenant 创建租户的核心流程
func (s *tenantService) CreateTenant(ctx context.Context, name, code, username string, userID int64) (int64, error) {
	// 1. 保存租户基本信息
	tenantID, err := s.repo.Create(ctx, domain.Tenant{
		Name:   name,
		Code:   code,
		Status: 1,
	})
	if err != nil {
		return 0, err
	}

	// 3. 将创建者加入该租户 (建立纯净契约关系)
	err = s.repo.AddMembership(ctx, userID, tenantID)
	if err != nil {
		return 0, err
	}

	return tenantID, err
}

func (s *tenantService) InitPersonalTenant(ctx context.Context, userId int64, username string) (int64, error) {
	// 初始化个人空间
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

func (s *tenantService) List(ctx context.Context, offset, limit int64) ([]domain.Tenant, int64, error) {
	total, err := s.repo.Count(ctx)
	if err != nil {
		return nil, 0, err
	}
	ts, err := s.repo.FindAll(ctx, offset, limit)
	return ts, total, err
}

func (s *tenantService) Update(ctx context.Context, t domain.Tenant) error {
	return s.repo.Update(ctx, t)
}

func (s *tenantService) Delete(ctx context.Context, id int64) error {
	return s.repo.Delete(ctx, id)
}

func (s *tenantService) GetByID(ctx context.Context, id int64) (domain.Tenant, error) {
	return s.repo.FindById(ctx, id)
}


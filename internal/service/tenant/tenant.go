package tenant

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
)

// ITenantService 租户业务接口
//
//go:generate mockgen -source=./tenant.go -package=tenantmocks -destination=./mocks/tenant.mock.go -typed ITenantService
type ITenantService interface {
	// CreateTenant 创建一个共享空间 (Org)
	CreateTenant(ctx context.Context, name, code string, ownerId int64) (int64, error)
	// InitPersonalTenant 为新用户初始化个人空间 (注册即拥有)
	InitPersonalTenant(ctx context.Context, userId int64, username string) (int64, error)
	// GetTenantsByUserId 查看用户属于哪些空间 (用于登录后选定或切换)
	GetTenantsByUserId(ctx context.Context, userId int64) ([]domain.Tenant, error)
	// CheckUserTenantAccess 校验用户是否有权进入该租户空间
	CheckUserTenantAccess(ctx context.Context, userId, tenantId int64) (bool, error)
}

type tenantService struct {
	repo repository.ITenantRepository
}

func NewTenantService(r repository.ITenantRepository) ITenantService {
	return &tenantService{repo: r}
}

// CreateTenant 创建租户的核心流程
func (s *tenantService) CreateTenant(ctx context.Context, name, code string, ownerId int64) (int64, error) {
	// 1. 保存租户基本信息
	tenantID, err := s.repo.Create(ctx, domain.Tenant{
		Name:    name,
		Code:    code,
		Type:    domain.TenantTypeOrg,
		OwnerID: ownerId,
		Status:  1,
	})
	if err != nil {
		return 0, err
	}

	// 2. 将创建者加入该租户作为初始管理员 (建立归属关系)
	err = s.repo.AddMember(ctx, domain.Member{
		TenantID: tenantID,
		UserID:   ownerId,
		Status:   1, // 活跃状态
	})

	return tenantID, err
}

func (s *tenantService) InitPersonalTenant(ctx context.Context, userId int64, username string) (int64, error) {
	// 这里通常用 "username-personal" 这种命名规则
	return s.repo.Create(ctx, domain.Tenant{
		Name:    username + "的个人空间",
		Code:    username + "-personal",
		Type:    domain.TenantTypePersonal,
		OwnerID: userId,
		Status:  1,
	})
}

func (s *tenantService) GetTenantsByUserId(ctx context.Context, userId int64) ([]domain.Tenant, error) {
	return s.repo.FindByUserId(ctx, userId)
}

func (s *tenantService) CheckUserTenantAccess(ctx context.Context, userId, tenantId int64) (bool, error) {
	// 目前简单实现：看用户是否在该租户的成员列表里
	// 未来的高级版本：可以校验用户在这个租户下的状态是否正常
	return s.repo.IsMember(ctx, tenantId, userId)
}

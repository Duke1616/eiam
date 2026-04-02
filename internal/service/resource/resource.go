package resource

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
)

// IResourceService 物理资源管理服务
//go:generate mockgen -source=./resource.go -package=resourcemocks -destination=./mocks/resource.mock.go -typed IResourceService
type IResourceService interface {
	// CreateAPI 注册 API
	CreateAPI(ctx context.Context, a domain.API) (int64, error)
	// FindAPIByPath 根据路径查找 API (供权限决策使用)
	FindAPIByPath(ctx context.Context, service, method, path string) (domain.API, error)
	
	// CreateMenu 注册菜单
	CreateMenu(ctx context.Context, m domain.Menu) (int64, error)
	// ListMenus 获取指定租户下的所有菜单 (供权限决策过滤使用)
	ListMenus(ctx context.Context, tenantId int64) ([]domain.Menu, error)
}

type resourceService struct {
	repo repository.IResourceRepository
}

func NewResourceService(repo repository.IResourceRepository) IResourceService {
	return &resourceService{repo: repo}
}

func (s *resourceService) CreateAPI(ctx context.Context, a domain.API) (int64, error) {
	return s.repo.CreateAPI(ctx, a)
}

func (s *resourceService) FindAPIByPath(ctx context.Context, service, method, path string) (domain.API, error) {
	return s.repo.FindAPIByPath(ctx, service, method, path)
}

func (s *resourceService) CreateMenu(ctx context.Context, m domain.Menu) (int64, error) {
	return s.repo.CreateMenu(ctx, m)
}

func (s *resourceService) ListMenus(ctx context.Context, tenantId int64) ([]domain.Menu, error) {
	return s.repo.ListMenus(ctx, tenantId)
}

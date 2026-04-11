package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
)

type IServiceRepository interface {
	BatchSave(ctx context.Context, services []domain.Service) error
	ListAll(ctx context.Context) ([]domain.Service, error)
	GetByCode(ctx context.Context, code string) (domain.Service, error)
}

type ServiceRepository struct {
	dao dao.IServiceDAO
}

func NewServiceRepository(dao dao.IServiceDAO) IServiceRepository {
	return &ServiceRepository{dao: dao}
}

func (r *ServiceRepository) BatchSave(ctx context.Context, services []domain.Service) error {
	daoServices := make([]dao.Service, 0, len(services))
	for _, s := range services {
		daoServices = append(daoServices, dao.Service{
			Code:        s.Code,
			Name:        s.Name,
			Description: s.Description,
		})
	}

	return r.dao.BatchUpsert(ctx, daoServices)
}

func (r *ServiceRepository) ListAll(ctx context.Context) ([]domain.Service, error) {
	list, err := r.dao.ListAll(ctx)
	if err != nil {
		return nil, err
	}

	res := make([]domain.Service, 0, len(list))
	for _, s := range list {
		res = append(res, r.toDomain(s))
	}
	return res, nil
}

func (r *ServiceRepository) GetByCode(ctx context.Context, code string) (domain.Service, error) {
	s, err := r.dao.GetByCode(ctx, code)
	if err != nil {
		return domain.Service{}, err
	}
	return r.toDomain(s), nil
}

func (r *ServiceRepository) toDomain(s dao.Service) domain.Service {
	return domain.Service{
		ID:          s.Id,
		Code:        s.Code,
		Name:        s.Name,
		Description: s.Description,
		Ctime:       s.Ctime,
		Utime:       s.Utime,
	}
}

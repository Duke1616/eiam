package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"github.com/samber/lo"
)

// IDepartmentRepository 部门仓储接口
type IDepartmentRepository interface {
	// Create 创建部门
	Create(ctx context.Context, d domain.Department) (int64, error)
	// Update 更新部门基本信息
	Update(ctx context.Context, d domain.Department) (int64, error)
	// Delete 删除部门
	Delete(ctx context.Context, id int64) error
	// GetByID 根据ID查询部门
	GetByID(ctx context.Context, id int64) (domain.Department, error)
	// ListAll 查询全部部门
	ListAll(ctx context.Context) ([]domain.Department, error)
	// ListByUserID 查询用户所在部门
	ListByUserID(ctx context.Context, userID int64) ([]domain.Department, error)
	// CountChildren 统计部门下的子部门数量
	CountChildren(ctx context.Context, id int64) (int64, error)

	// 部门-用户关系
	// BindUsers 批量将用户绑定至部门
	BindUsers(ctx context.Context, deptID int64, userIDs []int64) error
	// UnbindUsers 批量将用户从部门解绑
	UnbindUsers(ctx context.Context, deptID int64, userIDs []int64) error
	// ListMembers 分页查询部门成员列表，支持按关键字过滤
	ListMembers(ctx context.Context, deptID int64, offset, limit int64, keyword string) ([]domain.User, int64, error)
	// CountMembers 获取部门成员数量
	CountMembers(ctx context.Context, deptID int64) (int64, error)
}

type departmentRepository struct {
	dao      dao.IDepartmentDAO
	userRepo IUserRepository
}

func NewDepartmentRepository(dao dao.IDepartmentDAO, userRepo IUserRepository) IDepartmentRepository {
	return &departmentRepository{
		dao:      dao,
		userRepo: userRepo,
	}
}

func (repo *departmentRepository) Create(ctx context.Context, d domain.Department) (int64, error) {
	// 注入租户 ID
	tid := ctxutil.GetTenantID(ctx).Int64()
	entity := repo.toEntity(d)
	entity.TenantId = tid
	return repo.dao.Insert(ctx, entity)
}

func (repo *departmentRepository) Update(ctx context.Context, d domain.Department) (int64, error) {
	return repo.dao.Update(ctx, repo.toEntity(d))
}

func (repo *departmentRepository) Delete(ctx context.Context, id int64) error {
	return repo.dao.Delete(ctx, id)
}

func (repo *departmentRepository) GetByID(ctx context.Context, id int64) (domain.Department, error) {
	d, err := repo.dao.GetByID(ctx, id)
	if err != nil {
		return domain.Department{}, err
	}
	return repo.toDomain(d), nil
}

func (repo *departmentRepository) ListAll(ctx context.Context) ([]domain.Department, error) {
	ds, err := repo.dao.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	return lo.Map(ds, func(item dao.Department, _ int) domain.Department {
		return repo.toDomain(item)
	}), nil
}

func (repo *departmentRepository) ListByUserID(ctx context.Context, userID int64) ([]domain.Department, error) {
	ds, err := repo.dao.ListByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return lo.Map(ds, func(item dao.Department, _ int) domain.Department {
		return repo.toDomain(item)
	}), nil
}

func (repo *departmentRepository) CountChildren(ctx context.Context, id int64) (int64, error) {
	return repo.dao.CountChildren(ctx, id)
}

func (repo *departmentRepository) BindUsers(ctx context.Context, deptID int64, userIDs []int64) error {
	if len(userIDs) == 0 {
		return nil
	}
	tid := ctxutil.GetTenantID(ctx).Int64()
	bindings := make([]dao.UserDepartment, 0, len(userIDs))
	for _, uid := range userIDs {
		bindings = append(bindings, dao.UserDepartment{
			TenantId:     tid,
			UserId:       uid,
			DepartmentId: deptID,
		})
	}
	return repo.dao.BindUsers(ctx, bindings)
}

func (repo *departmentRepository) UnbindUsers(ctx context.Context, deptID int64, userIDs []int64) error {
	return repo.dao.UnbindUsers(ctx, deptID, userIDs)
}

func (repo *departmentRepository) ListMembers(ctx context.Context, deptID int64, offset, limit int64, keyword string) ([]domain.User, int64, error) {
	users, total, err := repo.dao.ListMembers(ctx, deptID, offset, limit, keyword)
	if err != nil || total == 0 {
		return nil, 0, err
	}

	userIDs := make([]int64, 0, len(users))
	for _, u := range users {
		userIDs = append(userIDs, u.ID)
	}

	domainUsers, err := repo.userRepo.FindByIds(ctx, userIDs)
	return domainUsers, total, err
}

func (repo *departmentRepository) CountMembers(ctx context.Context, deptID int64) (int64, error) {
	return repo.dao.CountMembers(ctx, deptID)
}

func (repo *departmentRepository) toDomain(d dao.Department) domain.Department {
	return domain.Department{
		ID:         d.Id,
		ParentID:   d.ParentId,
		Name:       d.Name,
		Sort:       d.Sort,
		Leaders:    d.Leaders.Val,
		MainLeader: d.MainLeader,
		Ctime:      d.Ctime,
		Utime:      d.Utime,
	}
}

func (repo *departmentRepository) toEntity(d domain.Department) dao.Department {
	return dao.Department{
		Id:         d.ID,
		ParentId:   d.ParentID,
		Name:       d.Name,
		Sort:       d.Sort,
		Leaders:    sqlx.JSONColumn[[]string]{Val: d.Leaders, Valid: true},
		MainLeader: d.MainLeader,
		Ctime:      d.Ctime,
		Utime:      d.Utime,
	}
}

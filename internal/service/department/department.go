package department

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
)

type departmentService struct {
	repo repository.IDepartmentRepository
}

func NewDepartmentService(repo repository.IDepartmentRepository) IDepartmentService {
	return &departmentService{
		repo: repo,
	}
}

func (s *departmentService) Create(ctx context.Context, d domain.Department) (int64, error) {
	return s.repo.Create(ctx, d)
}

func (s *departmentService) Update(ctx context.Context, d domain.Department) error {
	_, err := s.repo.Update(ctx, d)
	return err
}

func (s *departmentService) Delete(ctx context.Context, id int64) error {
	childrenCount, err := s.repo.CountChildren(ctx, id)
	if err != nil {
		return err
	}
	if childrenCount > 0 {
		return ErrDeleteDeptWithChildren
	}

	membersCount, err := s.repo.CountMembers(ctx, id)
	if err != nil {
		return err
	}
	if membersCount > 0 {
		return ErrDeleteDeptWithMembers
	}

	return s.repo.Delete(ctx, id)
}

func (s *departmentService) List(ctx context.Context) (domain.DepartmentTree, error) {
	departments, err := s.repo.ListAll(ctx)
	if err != nil {
		return nil, err
	}

	nodes := make(map[int64]*domain.DepartmentNode, len(departments))
	for _, d := range departments {
		nodes[d.ID] = &domain.DepartmentNode{
			Department: d,
			Children:   make([]*domain.DepartmentNode, 0),
		}
	}

	var tree domain.DepartmentTree
	for _, d := range departments {
		node := nodes[d.ID]
		if d.ParentID == 0 {
			tree = append(tree, node)
		} else {
			if parent, ok := nodes[d.ParentID]; ok {
				parent.Children = append(parent.Children, node)
			} else {
				tree = append(tree, node)
			}
		}
	}

	return tree, nil
}

func (s *departmentService) GetByID(ctx context.Context, id int64) (domain.Department, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *departmentService) AssignUsers(ctx context.Context, deptID int64, userIDs []int64) error {
	return s.repo.BindUsers(ctx, deptID, userIDs)
}

func (s *departmentService) RemoveUsers(ctx context.Context, deptID int64, userIDs []int64) error {
	return s.repo.UnbindUsers(ctx, deptID, userIDs)
}

func (s *departmentService) ListMembers(ctx context.Context, deptID int64, offset, limit int64, keyword string) ([]domain.User, int64, error) {
	return s.repo.ListMembers(ctx, deptID, offset, limit, keyword)
}

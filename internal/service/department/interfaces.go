package department

import (
	"context"
	"errors"

	"github.com/Duke1616/eiam/internal/domain"
)

type IDepartmentService interface {
	Create(ctx context.Context, d domain.Department) (int64, error)
	Update(ctx context.Context, d domain.Department) error
	Delete(ctx context.Context, id int64) error
	List(ctx context.Context) (domain.DepartmentTree, error)
	GetByID(ctx context.Context, id int64) (domain.Department, error)
	AssignUsers(ctx context.Context, deptID int64, userIDs []int64) error
	RemoveUsers(ctx context.Context, deptID int64, userIDs []int64) error
	ListMembers(ctx context.Context, deptID int64, offset, limit int64, keyword string) ([]domain.User, int64, error)
}

var (
	ErrDeleteDeptWithChildren = errors.New("不能删除含有子部门的部门")
	ErrDeleteDeptWithMembers  = errors.New("不能删除含有成员的部门")
)

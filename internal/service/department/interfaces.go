package department

import (
	"context"
	"errors"

	"github.com/Duke1616/eiam/internal/domain"
)

// IDepartmentService 部门服务接口
type IDepartmentService interface {
	// Create 新建部门
	Create(ctx context.Context, d domain.Department) (int64, error)
	// Update 修改部门基本信息
	Update(ctx context.Context, d domain.Department) error
	// Delete 删除部门，删除前会校验是否存在子部门或成员
	Delete(ctx context.Context, id int64) error
	// List 获取部门树
	List(ctx context.Context) (domain.DepartmentTree, error)
	// GetByID 根据ID获取部门详情
	GetByID(ctx context.Context, id int64) (domain.Department, error)
	// AssignUsers 批量添加用户到部门
	AssignUsers(ctx context.Context, deptID int64, userIDs []int64) error
	// RemoveUsers 从部门批量移出用户
	RemoveUsers(ctx context.Context, deptID int64, userIDs []int64) error
	// ListMembers 分页列出部门成员，支持模糊过滤
	ListMembers(ctx context.Context, deptID int64, offset, limit int64, keyword string) ([]domain.User, int64, error)
}

var (
	ErrDeleteDeptWithChildren = errors.New("不能删除含有子部门的部门")
	ErrDeleteDeptWithMembers  = errors.New("不能删除含有成员的部门")
)

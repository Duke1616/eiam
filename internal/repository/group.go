package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/samber/lo"
)

// IGroupRepository 用户组仓储接口
type IGroupRepository interface {
	// Create 创建用户组
	Create(ctx context.Context, g domain.Group) (int64, error)
	// Update 更新用户组基本信息
	Update(ctx context.Context, g domain.Group) (int64, error)
	// Delete 删除用户组及关联数据
	Delete(ctx context.Context, id int64) error
	// GetByCode 根据唯一编码查询用户组
	GetByCode(ctx context.Context, code string) (domain.Group, error)
	// GetByID 根据ID查询用户组
	GetByID(ctx context.Context, id int64) (domain.Group, error)
	// List 分页查询用户组列表
	List(ctx context.Context, offset, limit int64) ([]domain.Group, int64, error)
	// Search 分页模糊搜索用户组
	Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.Group, error)
	// CountSearch 模糊搜索匹配的用户组数量
	CountSearch(ctx context.Context, keyword string) (int64, error)

	// BindMembers 批量将用户绑定至用户组
	BindMembers(ctx context.Context, groupID int64, userIDs []int64) error
	// UnbindMembers 批量将用户从用户组解绑
	UnbindMembers(ctx context.Context, groupID int64, userIDs []int64) error
	// ListMembers 分页查询该用户组下的成员列表，支持按关键字过滤
	ListMembers(ctx context.Context, groupID int64, offset, limit int64, keyword string) ([]domain.User, int64, error)
	// CountMembers 获取该用户组下的成员数量
	CountMembers(ctx context.Context, groupID int64) (int64, error)
	// ListGroupsByUserID 分页查询用户所属的用户组列表，支持按关键字过滤
	ListGroupsByUserID(ctx context.Context, userID int64, offset, limit int64, keyword string) ([]domain.Group, int64, error)
	// ListGroupsByCodes 根据组编码列表分页查询用户组，支持按关键字过滤
	ListGroupsByCodes(ctx context.Context, codes []string, offset, limit int64, keyword string) ([]domain.Group, int64, error)
}

type groupRepository struct {
	dao      dao.IGroupDAO
	userRepo IUserRepository
}

func NewGroupRepository(dao dao.IGroupDAO, userRepo IUserRepository) IGroupRepository {
	return &groupRepository{
		dao:      dao,
		userRepo: userRepo,
	}
}

func (repo *groupRepository) Create(ctx context.Context, g domain.Group) (int64, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()
	entity := repo.toEntity(g)
	entity.TenantId = tid
	return repo.dao.Insert(ctx, entity)
}

func (repo *groupRepository) Update(ctx context.Context, g domain.Group) (int64, error) {
	return repo.dao.Update(ctx, repo.toEntity(g))
}

func (repo *groupRepository) Delete(ctx context.Context, id int64) error {
	return repo.dao.Delete(ctx, id)
}

func (repo *groupRepository) GetByCode(ctx context.Context, code string) (domain.Group, error) {
	g, err := repo.dao.GetByCode(ctx, code)
	if err != nil {
		return domain.Group{}, err
	}
	return repo.toDomain(g), nil
}

func (repo *groupRepository) GetByID(ctx context.Context, id int64) (domain.Group, error) {
	g, err := repo.dao.GetByID(ctx, id)
	if err != nil {
		return domain.Group{}, err
	}
	return repo.toDomain(g), nil
}

func (repo *groupRepository) List(ctx context.Context, offset, limit int64) ([]domain.Group, int64, error) {
	gs, total, err := repo.dao.List(ctx, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	res := lo.Map(gs, func(item dao.Group, _ int) domain.Group {
		return repo.toDomain(item)
	})
	return res, total, nil
}

func (repo *groupRepository) Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.Group, error) {
	gs, err := repo.dao.Search(ctx, offset, limit, keyword)
	if err != nil {
		return nil, err
	}
	res := lo.Map(gs, func(item dao.Group, _ int) domain.Group {
		return repo.toDomain(item)
	})
	return res, nil
}

func (repo *groupRepository) CountSearch(ctx context.Context, keyword string) (int64, error) {
	return repo.dao.CountSearch(ctx, keyword)
}

func (repo *groupRepository) BindMembers(ctx context.Context, groupID int64, userIDs []int64) error {
	if len(userIDs) == 0 {
		return nil
	}
	tid := ctxutil.GetTenantID(ctx).Int64()
	bindings := make([]dao.UserGroup, 0, len(userIDs))
	for _, uid := range userIDs {
		bindings = append(bindings, dao.UserGroup{
			TenantId: tid,
			UserId:   uid,
			GroupId:  groupID,
		})
	}
	return repo.dao.BindMembers(ctx, bindings)
}

func (repo *groupRepository) UnbindMembers(ctx context.Context, groupID int64, userIDs []int64) error {
	return repo.dao.UnbindMembers(ctx, groupID, userIDs)
}

func (repo *groupRepository) ListMembers(ctx context.Context, groupID int64, offset, limit int64, keyword string) ([]domain.User, int64, error) {
	users, total, err := repo.dao.ListMembers(ctx, groupID, offset, limit, keyword)
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

func (repo *groupRepository) CountMembers(ctx context.Context, groupID int64) (int64, error) {
	return repo.dao.CountMembers(ctx, groupID)
}

func (repo *groupRepository) ListGroupsByUserID(ctx context.Context, userID int64, offset, limit int64, keyword string) ([]domain.Group, int64, error) {
	gs, total, err := repo.dao.ListGroupsByUserID(ctx, userID, offset, limit, keyword)
	if err != nil {
		return nil, 0, err
	}
	res := lo.Map(gs, func(item dao.Group, _ int) domain.Group {
		return repo.toDomain(item)
	})
	return res, total, nil
}

func (repo *groupRepository) ListGroupsByCodes(ctx context.Context, codes []string, offset, limit int64, keyword string) ([]domain.Group, int64, error) {
	gs, total, err := repo.dao.ListGroupsByCodes(ctx, codes, offset, limit, keyword)
	if err != nil {
		return nil, 0, err
	}
	res := lo.Map(gs, func(item dao.Group, _ int) domain.Group {
		return repo.toDomain(item)
	})
	return res, total, nil
}

func (repo *groupRepository) toDomain(g dao.Group) domain.Group {
	return domain.Group{
		ID:    g.Id,
		Name:  g.Name,
		Code:  g.Code,
		Desc:  g.Desc,
		Ctime: g.Ctime,
		Utime: g.Utime,
	}
}

func (repo *groupRepository) toEntity(g domain.Group) dao.Group {
	return dao.Group{
		Id:    g.ID,
		Name:  g.Name,
		Code:  g.Code,
		Desc:  g.Desc,
		Ctime: g.Ctime,
		Utime: g.Utime,
	}
}

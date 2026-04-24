package repository

import (
	"context"
	"errors"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
)

// IUserRepository 用户仓储接口
type IUserRepository interface {
	// Create 创建新用户
	Create(ctx context.Context, u domain.User) (int64, error)
	// FindById 根据 ID 查找用户 (含全量关联信息)
	FindById(ctx context.Context, id int64) (domain.User, error)
	// FindByIds 批量根据 ID 获取基础用户对象
	FindByIds(ctx context.Context, ids []int64) ([]domain.User, error)
	// FindByUsername 根据用户名查找用户
	FindByUsername(ctx context.Context, username string) (domain.User, error)

	// Update 更新用户信息
	Update(ctx context.Context, u domain.User) (int64, error)
	// FindUserByIdentity 根据身份源标识查找用户
	FindUserByIdentity(ctx context.Context, provider, identityKey string) (domain.User, error)
	// SaveIdentity 绑定/更新用户第三方身份信息
	SaveIdentity(ctx context.Context, ui domain.UserIdentity) error

	// List 分页模糊查询用户列表
	List(ctx context.Context, offset, limit int64, keyword string) ([]domain.User, error)
	// ListMembers 分页模糊查询租户成员列表
	ListMembers(ctx context.Context, offset, limit int64, keyword string) ([]domain.User, error)
	// Count 统计搜索结果总数
	Count(ctx context.Context, keyword string) (int64, error)
	// CountMembers 统计租户成员总数
	CountMembers(ctx context.Context, keyword string) (int64, error)
	// Search 根据关键字模糊搜索当前租户成员用户
	Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.User, error)
	// CountSearch 根据关键字统计当前租户成员搜索结果总数
	CountSearch(ctx context.Context, keyword string) (int64, error)
	// GetAttachedUsersWithFilter 分页获取关联角色的用户详情，支持关键词过滤
	GetAttachedUsersWithFilter(ctx context.Context, roleCode string, offset, limit int64, keyword string) ([]domain.User, int64, error)
	// UpdateLastLoginAt 更新最近登录时间
	UpdateLastLoginAt(ctx context.Context, id int64, loginAt int64) error
	// Delete 删除用户
	Delete(ctx context.Context, id int64) error
	// BatchUpsert 批量 Upsert 用户数据
	BatchUpsert(ctx context.Context, users []domain.User) error
	// CheckUsersExist 批量检查用户名是否已经在系统中存在
	CheckUsersExist(ctx context.Context, usernames []string) (map[string]bool, error)
	// FindUsersByUsernames 批量根据用户名查找用户
	FindUsersByUsernames(ctx context.Context, usernames []string) ([]domain.User, error)
	// DeleteIdentity 解除身份源绑定
	DeleteIdentity(ctx context.Context, uid int64, provider string) error
}

type userRepository struct {
	dao  dao.IUserDAO
	tdao dao.ITenantDAO
}

func NewUserRepository(d dao.IUserDAO, td dao.ITenantDAO) IUserRepository {
	return &userRepository{
		dao:  d,
		tdao: td,
	}
}

func (repo *userRepository) Create(ctx context.Context, u domain.User) (int64, error) {
	id, err := repo.dao.Create(ctx, repo.toEntity(u))
	if err != nil {
		return 0, err
	}

	err = repo.dao.SaveProfile(ctx, dao.UserProfile{
		UserID:   id,
		Nickname: u.Profile.Nickname,
		Avatar:   u.Profile.Avatar,
		JobTitle: u.Profile.JobTitle,
		Phone:    u.Profile.Phone,
	})

	return id, err
}

func (repo *userRepository) FindById(ctx context.Context, id int64) (domain.User, error) {
	u, err := repo.dao.FindById(ctx, id)
	if err != nil {
		return domain.User{}, err
	}
	return repo.fullHydration(ctx, u)
}

func (repo *userRepository) FindByIds(ctx context.Context, ids []int64) ([]domain.User, error) {
	users, err := repo.dao.FindByIds(ctx, ids)
	if err != nil {
		return nil, err
	}
	return repo.batchHydration(ctx, users)
}

func (repo *userRepository) FindByUsername(ctx context.Context, username string) (domain.User, error) {
	u, err := repo.dao.FindByUsername(ctx, username)
	if err != nil {
		return domain.User{}, err
	}
	return repo.fullHydration(ctx, u)
}

func (repo *userRepository) fullHydration(ctx context.Context, u dao.User) (domain.User, error) {
	var (
		eg         errgroup.Group
		up         dao.UserProfile
		identities []dao.UserIdentity
	)

	eg.Go(func() error {
		var err error
		up, err = repo.dao.FindProfileByUserId(ctx, u.ID)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	})

	eg.Go(func() error {
		var err error
		identities, err = repo.dao.FindIdentitiesByUserId(ctx, u.ID)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	})

	if err := eg.Wait(); err != nil {
		return domain.User{}, err
	}

	return repo.toDomain(u, up, identities), nil
}

func (repo *userRepository) Update(ctx context.Context, u domain.User) (int64, error) {
	return repo.dao.Update(ctx, repo.toEntity(u), dao.UserProfile{
		UserID:   u.ID,
		Nickname: u.Profile.Nickname,
		Avatar:   u.Profile.Avatar,
		JobTitle: u.Profile.JobTitle,
		Phone:    u.Profile.Phone,
	})
}

func (repo *userRepository) FindUserByIdentity(ctx context.Context, provider, identityKey string) (domain.User, error) {
	y, err := repo.dao.FindIdentityByExternal(ctx, provider, identityKey)
	if err != nil {
		return domain.User{}, err
	}
	return repo.FindById(ctx, y.UserID)
}

func (repo *userRepository) SaveIdentity(ctx context.Context, ui domain.UserIdentity) error {
	return repo.dao.SaveIdentity(ctx, dao.UserIdentity{
		UserID:     ui.UserID,
		Provider:   ui.Provider,
		LdapInfo:   sqlx.JSONColumn[dao.LdapInfo]{Val: dao.LdapInfo(ui.LdapInfo), Valid: true},
		WechatInfo: sqlx.JSONColumn[dao.WechatInfo]{Val: dao.WechatInfo(ui.WechatInfo), Valid: true},
		FeishuInfo: sqlx.JSONColumn[dao.FeishuInfo]{Val: dao.FeishuInfo(ui.FeishuInfo), Valid: true},
	})
}

func (repo *userRepository) List(ctx context.Context, offset, limit int64, keyword string) ([]domain.User, error) {
	us, err := repo.dao.List(ctx, offset, limit, keyword)
	if err != nil {
		return nil, err
	}
	return repo.batchHydration(ctx, us)
}

func (repo *userRepository) Count(ctx context.Context, keyword string) (int64, error) {
	return repo.dao.Count(ctx, keyword)
}

func (repo *userRepository) ListMembers(ctx context.Context, offset, limit int64, keyword string) ([]domain.User, error) {
	us, err := repo.dao.ListMembers(ctx, offset, limit, keyword)
	if err != nil {
		return nil, err
	}
	return repo.batchHydration(ctx, us)
}

func (repo *userRepository) CountMembers(ctx context.Context, keyword string) (int64, error) {
	return repo.dao.CountMembers(ctx, keyword)
}

func (repo *userRepository) Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.User, error) {
	users, err := repo.dao.Search(ctx, keyword, offset, limit)
	if err != nil {
		return nil, err
	}

	return repo.batchHydration(ctx, users)
}

func (repo *userRepository) CountSearch(ctx context.Context, keyword string) (int64, error) {
	return repo.dao.CountSearch(ctx, keyword)
}

func (repo *userRepository) GetAttachedUsersWithFilter(ctx context.Context, roleCode string, offset, limit int64, keyword string) ([]domain.User, int64, error) {
	users, total, err := repo.dao.GetAttachedUsersWithFilter(ctx, roleCode, offset, limit, keyword)
	if err != nil {
		return nil, 0, err
	}

	res, err := repo.batchHydration(ctx, users)
	return res, total, err
}

func (repo *userRepository) batchHydration(ctx context.Context, users []dao.User) ([]domain.User, error) {
	if len(users) == 0 {
		return []domain.User{}, nil
	}

	// 1. 收集所有 user_id
	userIDs := make([]int64, 0, len(users))
	for _, u := range users {
		userIDs = append(userIDs, u.ID)
	}

	// 2. 并行批量查询 profiles 和 identities
	var (
		eg            errgroup.Group
		profiles      []dao.UserProfile
		allIdentities []dao.UserIdentity
	)

	eg.Go(func() error {
		var err error
		profiles, err = repo.dao.FindProfilesByUserIds(ctx, userIDs)
		return err
	})

	eg.Go(func() error {
		var err error
		allIdentities, err = repo.dao.FindIdentitiesByUserIds(ctx, userIDs)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	// 3. 构建 user_id -> profile 映射
	userToProfile := make(map[int64]dao.UserProfile)
	for _, p := range profiles {
		userToProfile[p.UserID] = p
	}

	// 4. 构建 user_id -> identities 映射
	userToIdentities := make(map[int64][]dao.UserIdentity)
	for _, identity := range allIdentities {
		userToIdentities[identity.UserID] = append(userToIdentities[identity.UserID], identity)
	}

	// 5. 组装结果
	res := make([]domain.User, 0, len(users))
	for _, u := range users {
		profile := userToProfile[u.ID]
		identities := userToIdentities[u.ID]

		res = append(res, repo.toDomain(u, profile, identities))
	}

	return res, nil
}

func (repo *userRepository) toDomain(u dao.User, up dao.UserProfile, ids []dao.UserIdentity) domain.User {
	identities := make([]domain.UserIdentity, 0, len(ids))
	for _, id := range ids {
		identities = append(identities, domain.UserIdentity{
			UserID:     id.UserID,
			Provider:   id.Provider,
			LdapInfo:   domain.LdapInfo(id.LdapInfo.Val),
			WechatInfo: domain.WechatInfo(id.WechatInfo.Val),
			FeishuInfo: domain.FeishuInfo(id.FeishuInfo.Val),
		})
	}

	return domain.User{
		ID:          u.ID,
		Username:    u.Username,
		Password:    u.Password,
		Email:       u.Email,
		Status:      domain.Status(u.Status),
		Source:      domain.Source(u.Source),
		Ctime:       u.Ctime,
		Utime:       u.Utime,
		LastLoginAt: u.LastLoginAt,
		Profile: domain.UserProfile{
			UserID:   up.UserID,
			Nickname: up.Nickname,
			Avatar:   up.Avatar,
			JobTitle: up.JobTitle,
			Phone:    up.Phone,
		},
		Identities: identities,
	}
}

func (repo *userRepository) toEntity(u domain.User) dao.User {
	return dao.User{
		ID:          u.ID,
		Username:    u.Username,
		Password:    u.Password,
		Email:       u.Email,
		Status:      int(u.Status),
		Source:      u.Source.String(),
		Ctime:       u.Ctime,
		Utime:       u.Utime,
		LastLoginAt: u.LastLoginAt,
	}
}

func (repo *userRepository) UpdateLastLoginAt(ctx context.Context, id int64, loginAt int64) error {
	return repo.dao.UpdateLastLoginAt(ctx, id, loginAt)
}

func (repo *userRepository) Delete(ctx context.Context, id int64) error {
	return repo.dao.Delete(ctx, id)
}

func (repo *userRepository) DeleteIdentity(ctx context.Context, uid int64, provider string) error {
	return repo.dao.DeleteIdentity(ctx, uid, provider)
}

func (repo *userRepository) BatchUpsert(ctx context.Context, users []domain.User) error {
	if len(users) == 0 {
		return nil
	}

	daoUsers := lo.Map(users, func(u domain.User, _ int) dao.User { return repo.toEntity(u) })
	usernames := lo.Map(users, func(u domain.User, _ int) string { return u.Username })

	// 1. 批量同步基础用户
	if err := repo.dao.BatchUpsertUsers(ctx, daoUsers); err != nil {
		return err
	}

	// 2. 获取最新 ID 映射
	savedUsers, err := repo.dao.FindUsersByUsernames(ctx, usernames)
	if err != nil {
		return err
	}

	idMap := lo.SliceToMap(savedUsers, func(u dao.User) (string, int64) {
		return u.Username, u.ID
	})

	// 3. 构建关联数据
	profiles := lo.FilterMap(users, func(u domain.User, _ int) (dao.UserProfile, bool) {
		uid, ok := idMap[u.Username]
		return dao.UserProfile{
			UserID:   uid,
			Nickname: u.Profile.Nickname,
			Avatar:   u.Profile.Avatar,
			JobTitle: u.Profile.JobTitle,
		}, ok
	})

	identities := lo.FlatMap(users, func(u domain.User, _ int) []dao.UserIdentity {
		uid, ok := idMap[u.Username]
		if !ok {
			return nil
		}

		return lo.Map(u.Identities, func(id domain.UserIdentity, _ int) dao.UserIdentity {
			return dao.UserIdentity{
				UserID:     uid,
				Provider:   id.Provider,
				LdapInfo:   sqlx.JSONColumn[dao.LdapInfo]{Val: dao.LdapInfo(id.LdapInfo), Valid: true},
				WechatInfo: sqlx.JSONColumn[dao.WechatInfo]{Val: dao.WechatInfo(id.WechatInfo), Valid: true},
				FeishuInfo: sqlx.JSONColumn[dao.FeishuInfo]{Val: dao.FeishuInfo(id.FeishuInfo), Valid: true},
			}
		})
	})

	// 4. 批量同步关联数据
	return repo.dao.BatchUpsertProfilesAndIdentities(ctx, profiles, identities)
}

func (repo *userRepository) CheckUsersExist(ctx context.Context, usernames []string) (map[string]bool, error) {
	if len(usernames) == 0 {
		return map[string]bool{}, nil
	}
	exists, err := repo.dao.FindUsersByUsernames(ctx, usernames)
	if err != nil {
		return nil, err
	}

	res := make(map[string]bool, len(exists))
	for _, u := range exists {
		res[u.Username] = true
	}
	return res, nil
}
func (repo *userRepository) FindUsersByUsernames(ctx context.Context, usernames []string) ([]domain.User, error) {
	users, err := repo.dao.FindUsersByUsernames(ctx, usernames)
	if err != nil {
		return nil, err
	}

	return lo.Map(users, func(u dao.User, _ int) domain.User {
		return domain.User{
			ID:       u.ID,
			Username: u.Username,
		}
	}), nil
}

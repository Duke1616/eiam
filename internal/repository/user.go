package repository

import (
	"context"
	"errors"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
)

// IUserRepository 用户仓储接口
type IUserRepository interface {
	// Create 创建新用户
	Create(ctx context.Context, u domain.User) (int64, error)
	// FindById 根据 ID 查找用户 (含全量关联信息)
	FindById(ctx context.Context, id int64) (domain.User, error)
	// FindByUsername 根据用户名查找用户
	FindByUsername(ctx context.Context, username string) (domain.User, error)

	// Update 更新用户信息
	Update(ctx context.Context, u domain.User) (int64, error)
	// FindUserByIdentity 根据身份源标识查找用户
	FindUserByIdentity(ctx context.Context, provider, identityKey string) (domain.User, error)
	// SaveIdentity 绑定/更新用户第三方身份信息
	SaveIdentity(ctx context.Context, ui domain.UserIdentity) error

	// List 分页获取用户列表
	List(ctx context.Context, offset, limit int64) ([]domain.User, error)
	// Count 获取用户总数
	Count(ctx context.Context) (int64, error)
	// Search 根据关键字模糊搜索用户 (支持用户名、昵称)
	Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.User, error)
	// CountByKeyword 根据关键字统计搜索结果总数
	CountByKeyword(ctx context.Context, keyword string) (int64, error)
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

func (repo *userRepository) List(ctx context.Context, offset, limit int64) ([]domain.User, error) {
	us, err := repo.dao.List(ctx, offset, limit)
	if err != nil {
		return nil, err
	}
	res := make([]domain.User, 0, len(us))
	for _, u := range us {
		d, _ := repo.fullHydration(ctx, u)
		res = append(res, d)
	}
	return res, nil
}

func (repo *userRepository) Count(ctx context.Context) (int64, error) {
	return repo.dao.Count(ctx)
}

func (repo *userRepository) CountByKeyword(ctx context.Context, keyword string) (int64, error) {
	return repo.dao.CountByKeyword(ctx, keyword)
}

func (repo *userRepository) Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.User, error) {
	if keyword == "" {
		return repo.List(ctx, offset, limit)
	}

	users, err := repo.dao.Search(ctx, keyword, offset, limit)
	if err != nil {
		return nil, err
	}

	return repo.batchHydration(ctx, users)
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
		ID:       u.ID,
		Username: u.Username,
		Password: u.Password,
		Email:    u.Email,
		Status:   domain.Status(u.Status),
		Ctime:    u.Ctime,
		Utime:    u.Utime,
		Profile: domain.UserProfile{
			UserID:   up.UserID,
			Nickname: up.Nickname,
			Avatar:   up.Avatar,
			JobTitle: up.JobTitle,
		},
		Identities: identities,
	}
}

func (repo *userRepository) toEntity(u domain.User) dao.User {
	return dao.User{
		ID:       u.ID,
		Username: u.Username,
		Password: u.Password,
		Email:    u.Email,
		Status:   int(u.Status),
		Ctime:    u.Ctime,
		Utime:    u.Utime,
	}
}

package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"golang.org/x/sync/errgroup"
)

// IUserRepository 用户仓储接口
type IUserRepository interface {
	Create(ctx context.Context, u domain.User) (int64, error)
	FindById(ctx context.Context, id int64) (domain.User, error)
	FindByUsername(ctx context.Context, username string) (domain.User, error)

	Update(ctx context.Context, u domain.User) (int64, error)
	FindUserByIdentity(ctx context.Context, provider, identityKey string) (domain.User, error)
	SaveIdentity(ctx context.Context, ui domain.UserIdentity) error

	List(ctx context.Context, offset, limit int64) ([]domain.User, error)
	Count(ctx context.Context) (int64, error)
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
	return repo.dao.Create(ctx, repo.toEntity(u))
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
		membership, err := repo.tdao.GetMembershipByUserId(ctx, u.ID)
		if err != nil {
			return nil
		}
		up, _ = repo.dao.FindProfileByMembershipId(ctx, membership.ID)
		return nil
	})

	eg.Go(func() error {
		identities, _ = repo.dao.FindIdentitiesByUserId(ctx, u.ID)
		return nil
	})

	if err := eg.Wait(); err != nil {
		return domain.User{}, err
	}

	return repo.toDomain(u, up, identities), nil
}

func (repo *userRepository) Update(ctx context.Context, u domain.User) (int64, error) {
	return repo.dao.Update(ctx, repo.toEntity(u), dao.UserProfile{
		MembershipID: u.Profile.MembershipID,
		Nickname:     u.Profile.Nickname,
		Avatar:       u.Profile.Avatar,
		JobTitle:     u.Profile.JobTitle,
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
			MembershipID: up.MembershipID,
			Nickname:     up.Nickname,
			Avatar:       up.Avatar,
			JobTitle:     up.JobTitle,
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

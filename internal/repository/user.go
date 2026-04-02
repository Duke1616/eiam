package repository

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"golang.org/x/sync/errgroup"
)

// IUserRepository 用户仓储接口：聚合账号、资料及身份映射的顶级访问点
type IUserRepository interface {
	// Create 创建用户账号及关联资料
	Create(ctx context.Context, u domain.User) (int64, error)
	// Update 批量更新账号和详情资料
	Update(ctx context.Context, u domain.User) (int64, error)

	// FindById 在 Repository 层手动聚合三表数据（User, UserInfo, Identity），完全替代 JOIN
	FindById(ctx context.Context, id int64) (domain.User, error)
	// FindByUsername 在 Repository 层执行多表 Hydration 聚合查询
	FindByUsername(ctx context.Context, username string) (domain.User, error)

	// List 分页获取账号列表，通常非聚合查询
	List(ctx context.Context, offset, limit int64) ([]domain.User, error)
	// Count 获取租户下总账号数量
	Count(ctx context.Context) (int64, error)

	// SaveIdentity 维护身份联邦映射：绑定 LDAP, Feishu 等外部账号
	SaveIdentity(ctx context.Context, ui domain.UserIdentity) error
	// FindUserByIdentity 跨源查询：通过外部标识反查聚合后的领域对象
	FindUserByIdentity(ctx context.Context, provider, externalID string) (domain.User, error)
}

type userRepository struct {
	dao dao.IUserDAO
}

func NewUserRepository(d dao.IUserDAO) IUserRepository {
	return &userRepository{dao: d}
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

func (repo *userRepository) FindUserByIdentity(ctx context.Context, provider, externalID string) (domain.User, error) {
	idty, err := repo.dao.FindIdentityByExternal(ctx, provider, externalID)
	if err != nil {
		return domain.User{}, err
	}

	return repo.FindById(ctx, idty.UserID)
}

// fullHydration 在应用层执行多表数据“拼图”：完全替代数据库 Join
func (repo *userRepository) fullHydration(ctx context.Context, u dao.User) (domain.User, error) {
	var (
		eg         errgroup.Group
		ui         dao.UserInfo
		identities []dao.UserIdentity
	)

	// 并行加载资料和联邦身份，追求极致响应速度
	eg.Go(func() error {
		var err error
		ui, err = repo.dao.FindInfoByUserId(ctx, u.ID)
		return err
	})

	eg.Go(func() error {
		var err error
		identities, err = repo.dao.FindIdentitiesByUserId(ctx, u.ID)
		return err
	})

	return repo.toDomain(u, ui, identities), eg.Wait()
}

func (repo *userRepository) Create(ctx context.Context, u domain.User) (int64, error) {
	return repo.dao.Create(ctx, repo.toEntity(u), repo.toInfoEntity(u))
}

func (repo *userRepository) SaveIdentity(ctx context.Context, ui domain.UserIdentity) error {
	return repo.dao.SaveIdentity(ctx, dao.UserIdentity{
		UserID:     ui.UserID,
		Provider:   ui.Provider,
		ExternalID: ui.ExternalID,
		Extra:      sqlx.JSONColumn[map[string]string]{Val: ui.Extra},
	})
}

// toDomain 实现从 Ctime/Utime (int64) 到 CreatedAt/UpdatedAt (time.Time) 的透明转换
func (repo *userRepository) toDomain(u dao.User, ui dao.UserInfo, ids []dao.UserIdentity) domain.User {
	identities := make([]domain.UserIdentity, 0, len(ids))
	for _, id := range ids {
		identities = append(identities, domain.UserIdentity{
			ID:         id.ID,
			UserID:     id.UserID,
			Provider:   id.Provider,
			ExternalID: id.ExternalID,
			Extra:      id.Extra.Val,
		})
	}

	return domain.User{
		ID:        u.ID,
		Username:  u.Username,
		Password:  u.Password,
		Email:     u.Email,
		Status:    domain.Status(u.Status),
		TenantID:  u.TenantID,
		CreatedAt: time.Unix(u.Ctime, 0), // 适配 int64 时间戳
		UpdatedAt: time.Unix(u.Utime, 0),
		Profile: domain.UserInfo{
			Nickname: ui.Nickname,
			Avatar:   ui.Avatar,
			JobTitle: ui.JobTitle,
			Metadata: ui.Metadata.Val,
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
		TenantID: u.TenantID,
		Ctime:    u.CreatedAt.Unix(),
		Utime:    u.UpdatedAt.Unix(),
	}
}

func (repo *userRepository) toInfoEntity(u domain.User) dao.UserInfo {
	return dao.UserInfo{
		UserID:   u.ID,
		Nickname: u.Profile.Nickname,
		Avatar:   u.Profile.Avatar,
		JobTitle: u.Profile.JobTitle,
		Metadata: sqlx.JSONColumn[map[string]string]{Val: u.Profile.Metadata},
	}
}

func (repo *userRepository) Update(ctx context.Context, u domain.User) (int64, error) {
	return repo.dao.Update(ctx, repo.toEntity(u), repo.toInfoEntity(u))
}

func (repo *userRepository) List(ctx context.Context, offset, limit int64) ([]domain.User, error) {
	us, err := repo.dao.List(ctx, offset, limit)
	if err != nil {
		return nil, err
	}
	res := make([]domain.User, 0, len(us))
	for _, u := range us {
		// 分页列表通常不需要聚合所有身份信息，按需返回基础对象
		res = append(res, repo.toDomain(u, dao.UserInfo{}, nil))
	}
	return res, nil
}

func (repo *userRepository) Count(ctx context.Context) (int64, error) {
	return repo.dao.Count(ctx)
}

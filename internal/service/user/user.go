package user

import (
	"context"
	"errors"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/tenant"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"golang.org/x/crypto/bcrypt"
)

type IUserService interface {
	Signup(ctx context.Context, u domain.User) (int64, error)
	// Login 认证成功后，同步返回封装好的 LoginResult：
	// Result.TenantID != 0 → 单租户，直接颁发正式 JWT
	// Result.TenantID == 0 → 多租户，前端从 Result.Tenants 选择后调 SwitchTenant
	Login(ctx context.Context, provider, username, password string) (domain.LoginResult, error)

	GetById(ctx context.Context, id int64) (domain.User, error)
	GetByUsername(ctx context.Context, username string) (domain.User, error)

	SwitchTenant(ctx context.Context, uid int64, targetTenantID int64) (domain.User, error)

	List(ctx context.Context, offset, limit int64) ([]domain.User, int64, error)
	Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.User, error)
	// CountByKeyword 根据关键词获取符合条件的用户总数
	CountByKeyword(ctx context.Context, keyword string) (int64, error)
	Update(ctx context.Context, u domain.User) (int64, error)
	UpdatePassword(ctx context.Context, uid int64, oldPassword, newPassword string) error
	// Delete 删除用户
	Delete(ctx context.Context, id int64) error

	// CheckUsersExist 批量检查用户名是否存在
	CheckUsersExist(ctx context.Context, usernames []string) (map[string]bool, error)
}

type userService struct {
	repo      repository.IUserRepository
	tenantSvc tenant.ITenantService
	providers map[string]domain.IdentityProvider
}

func NewUserService(r repository.IUserRepository, tenantSvc tenant.ITenantService, ps []domain.IdentityProvider) IUserService {
	registry := make(map[string]domain.IdentityProvider, len(ps))
	for _, p := range ps {
		registry[p.Name()] = p
	}
	return &userService{
		repo:      r,
		tenantSvc: tenantSvc,
		providers: registry,
	}
}

func (s *userService) Login(ctx context.Context, provider, username, password string) (domain.LoginResult, error) {
	if provider == "local" || provider == "" {
		return s.loginLocal(ctx, username, password)
	}

	return s.loginExternal(ctx, provider, username, password)
}

func (s *userService) loginLocal(ctx context.Context, username, password string) (domain.LoginResult, error) {
	u, err := s.repo.FindByUsername(ctx, username)
	if err != nil {
		return domain.LoginResult{}, errs.ErrInvalidUser
	}

	if err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)); err != nil {
		return domain.LoginResult{}, errs.ErrInvalidUser
	}

	return s.postLogin(ctx, u)
}

func (s *userService) loginExternal(ctx context.Context, providerName string, username, password string) (domain.LoginResult, error) {
	strategy, ok := s.providers[providerName]
	if !ok {
		return domain.LoginResult{}, errs.ErrProviderNotFound
	}

	extUser, err := strategy.Authenticate(ctx, username, password)
	if err != nil {
		return domain.LoginResult{}, err
	}

	id, ok := extUser.GetPrimaryIdentity(providerName)
	if !ok {
		return domain.LoginResult{}, errs.ErrProviderNotFound
	}

	// 老用户：进入后续租户路由
	localUser, err := s.repo.FindUserByIdentity(ctx, providerName, id.IdentityKey())
	if err == nil {
		return s.postLogin(ctx, localUser)
	}

	// 新用户：JIT 开荒 → 创建账号 + 绑定身份 + 初始化个人空间
	u, tenantID, err := s.provisionOnLogin(ctx, extUser, id)
	if err != nil {
		return domain.LoginResult{}, err
	}

	// 新用户只有一个刚建好的空间，直接返回
	return domain.LoginResult{
		User:     u,
		TenantID: tenantID,
		Tenants:  []domain.Tenant{{ID: tenantID}},
	}, nil
}

// postLogin 认证后公共逻辑：查询租户列表并决定路由
func (s *userService) postLogin(ctx context.Context, u domain.User) (domain.LoginResult, error) {
	tenants, err := s.tenantSvc.GetTenantsByUserId(ctx, u.ID)
	if err != nil || len(tenants) == 0 {
		return domain.LoginResult{}, errors.New("用户无可用租户空间")
	}

	// 单租户：直接加载该空间下的名片并返回确定的 tenantID
	if len(tenants) == 1 {
		tID := tenants[0].ID
		fullUser, err := s.repo.FindById(ctxutil.WithTenantID(ctx, tID), u.ID)
		if err != nil {
			return domain.LoginResult{}, err
		}
		return domain.LoginResult{User: fullUser, TenantID: tID, Tenants: tenants}, nil
	}

	// 多租户：TenantID 为 0，由前端从 Tenants 列表中选择后调 SwitchTenant
	return domain.LoginResult{User: u, TenantID: 0, Tenants: tenants}, nil
}

func (s *userService) SwitchTenant(ctx context.Context, uid int64, targetTenantID int64) (domain.User, error) {
	// 直接复用 CheckUserTenantAccess 校验 Membership 合约是否存在
	hasAccess, err := s.tenantSvc.CheckUserTenantAccess(ctx, uid, targetTenantID)
	if err != nil {
		return domain.User{}, err
	}

	if !hasAccess {
		return domain.User{}, errs.ErrTenantAccessDenied
	}

	return s.repo.FindById(ctxutil.WithTenantID(ctx, targetTenantID), uid)
}

func (s *userService) provisionOnLogin(ctx context.Context, ext domain.User, id domain.UserIdentity) (domain.User, int64, error) {
	uid, err := s.ensureGlobalUser(ctx, ext)
	if err != nil {
		return domain.User{}, 0, err
	}

	if err = s.bindGlobalIdentity(ctx, uid, id); err != nil {
		return domain.User{}, 0, err
	}

	personalTenantID, err := s.tenantSvc.InitPersonalTenant(ctx, uid, ext.Username)
	if err != nil {
		return domain.User{}, 0, err
	}

	newCtx := ctxutil.WithTenantID(ctx, personalTenantID)
	u, err := s.repo.FindById(newCtx, uid)
	if err != nil {
		return domain.User{}, 0, err
	}

	u.Profile.Nickname = ext.Profile.Nickname
	u.Profile.JobTitle = ext.Profile.JobTitle
	if _, err = s.repo.Update(newCtx, u); err != nil {
		return domain.User{}, 0, err
	}

	return u, personalTenantID, nil
}

func (s *userService) ensureGlobalUser(ctx context.Context, ext domain.User) (int64, error) {
	u, err := s.repo.FindByUsername(ctx, ext.Username)
	if err == nil {
		return u.ID, nil
	}
	return s.Signup(ctx, ext)
}

func (s *userService) bindGlobalIdentity(ctx context.Context, uid int64, id domain.UserIdentity) error {
	id.UserID = uid
	return s.repo.SaveIdentity(ctx, id)
}

func (s *userService) Signup(ctx context.Context, u domain.User) (int64, error) {
	_, err := s.repo.FindByUsername(ctx, u.Username)
	if err == nil {
		return 0, errs.ErrUserExist
	}

	if u.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			return 0, err
		}
		u.Password = string(hash)
	}
	return s.repo.Create(ctx, u)
}

func (s *userService) UpdatePassword(ctx context.Context, uid int64, oldPassword, newPassword string) error {
	u, err := s.repo.FindById(ctx, uid)
	if err != nil {
		return err
	}

	// 校验旧密码
	if err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(oldPassword)); err != nil {
		return errs.ErrInvalidUser
	}

	// 加密新密码
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.Password = string(hash)
	_, err = s.repo.Update(ctx, u)
	return err
}

func (s *userService) GetById(ctx context.Context, id int64) (domain.User, error) {
	return s.repo.FindById(ctx, id)
}

func (s *userService) GetByUsername(ctx context.Context, username string) (domain.User, error) {
	return s.repo.FindByUsername(ctx, username)
}

func (s *userService) List(ctx context.Context, offset, limit int64) ([]domain.User, int64, error) {
	if ctxutil.GetTenantID(ctx) != 0 {
		total, err := s.repo.CountTenantMembers(ctx)
		if err != nil {
			return nil, 0, err
		}

		us, err := s.repo.ListByTenantMembership(ctx, offset, limit)
		return us, total, err
	}

	total, err := s.repo.Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	us, err := s.repo.List(ctx, offset, limit)
	return us, total, err
}

func (s *userService) Search(ctx context.Context, keyword string, offset, limit int64) ([]domain.User, error) {
	if limit <= 0 {
		return []domain.User{}, nil
	}
	return s.repo.Search(ctx, keyword, offset, limit)
}

func (s *userService) CountByKeyword(ctx context.Context, keyword string) (int64, error) {
	return s.repo.CountByKeyword(ctx, keyword)
}

func (s *userService) Update(ctx context.Context, u domain.User) (int64, error) {
	return s.repo.Update(ctx, u)
}

func (s *userService) Delete(ctx context.Context, id int64) error {
	return s.repo.Delete(ctx, id)
}

func (s *userService) CheckUsersExist(ctx context.Context, usernames []string) (map[string]bool, error) {
	return s.repo.CheckUsersExist(ctx, usernames)
}

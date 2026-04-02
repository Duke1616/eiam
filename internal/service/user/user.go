package user

import (
	"context"
	"errors"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

var ErrUserExist = errors.New("用户名已存在")
var ErrInvalidUser = errors.New("账号或密码错误")
var ErrProviderNotFound = errors.New("未找到指定的身份源适配器")

// IUserService 用户业务逻辑接口：封装账号治理与身份映射的核心业务流
//
//go:generate mockgen -source=./user.go -package=usermocks -destination=./mocks/user.mock.go -typed IUserService
type IUserService interface {
	// Signup 注册新本地用户
	Signup(ctx context.Context, u domain.User) (int64, error)
	// Login 统一登录入口：根据 provider 自动分发认证逻辑 (local, ldap, feishu 等)
	Login(ctx context.Context, provider, username, password string) (domain.User, error)
	// GetById 根据 ID 获取聚合后的全量用户信息 (含 Profile 和 Identities)
	GetById(ctx context.Context, id int64) (domain.User, error)
	// GetByUsername 按用户名获取全量用户信息
	GetByUsername(ctx context.Context, username string) (domain.User, error)
	// List 分页获取账号清单
	List(ctx context.Context, offset, limit int64) ([]domain.User, int64, error)
	// Update 修改用户账号信息或详情资料
	Update(ctx context.Context, u domain.User) (int64, error)
}

type userService struct {
	repo      repository.IUserRepository
	providers map[string]IdentityProvider // 注册各种联邦身份源: ldap, feishu...
}

func NewUserService(r repository.IUserRepository, ps []IdentityProvider) IUserService {
	registry := make(map[string]IdentityProvider, len(ps))
	for _, p := range ps {
		registry[p.Name()] = p
	}
	return &userService{
		repo:      r,
		providers: registry,
	}
}

func (s *userService) Login(ctx context.Context, provider, username, password string) (domain.User, error) {
	// 1. 统一调度：判别是否为本地认证
	if provider == "local" || provider == "" {
		return s.loginLocal(ctx, username, password)
	}

	// 2. 统一调度：执行联邦身份认证 (LDAP, Feishu 等)
	return s.loginExternal(ctx, provider, username, password)
}

// loginLocal 私有本地登录逻辑：本地 DB 账密校验
func (s *userService) loginLocal(ctx context.Context, username, password string) (domain.User, error) {
	u, err := s.repo.FindByUsername(ctx, username)
	if err != nil {
		return domain.User{}, ErrInvalidUser
	}

	// 校验 Bcrypt 加密后的密码
	if err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)); err != nil {
		return domain.User{}, ErrInvalidUser
	}

	return u, nil
}

// loginExternal 私有联邦登录逻辑：外部认证 + JIT 自动建号/同步
func (s *userService) loginExternal(ctx context.Context, providerName string, username, password string) (domain.User, error) {
	// 找到对应的认证策略 (如 LDAP 实现)
	p, ok := s.providers[providerName]
	if !ok {
		return domain.User{}, ErrProviderNotFound
	}

	// 1. 外部协议层认证：获取标准化外部资料 (含 ExternalID)
	extProfile, err := p.Authenticate(ctx, username, password)
	if err != nil {
		return domain.User{}, err
	}

	// 2. 身份联邦查询：根据全球唯一标识 (DN/OpenID) 查找系统内关联的本地 User
	user, err := s.repo.FindUserByIdentity(ctx, providerName, extProfile.ExternalID)
	if err == nil {
		// 登录成功：命中已有的绑定关系
		return user, nil
	}

	// 3. JIT (Just-In-Time) 预配模式：用户在本地不存在，触发自动建号/绑定
	u := domain.User{
		Username: extProfile.Username,
		Email:    extProfile.Email,
		Status:   domain.StatusActive,
		Profile: domain.UserInfo{
			Nickname: extProfile.Nickname,
			JobTitle: extProfile.JobTitle,
			Metadata: extProfile.Extra,
		},
	}

	// 执行注册流程 (账号+资料)
	id, err := s.Signup(ctx, u)
	if err != nil {
		return domain.User{}, err
	}
	u.ID = id

	// 4. 完成联邦绑定：为新账号建立 Identity 映射
	err = s.repo.SaveIdentity(ctx, domain.UserIdentity{
		UserID:     u.ID,
		Provider:   providerName,
		ExternalID: extProfile.ExternalID,
		Extra:      extProfile.Extra,
	})

	return u, err
}

func (s *userService) Signup(ctx context.Context, u domain.User) (int64, error) {
	// 本地密码入库执行 Bcrypt 加密 (外部 JIT 用户通常不需要本地密码或随机生成)
	if u.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			return 0, err
		}
		u.Password = string(hash)
	}

	return s.repo.Create(ctx, u)
}

func (s *userService) GetById(ctx context.Context, id int64) (domain.User, error) {
	return s.repo.FindById(ctx, id)
}

func (s *userService) GetByUsername(ctx context.Context, username string) (domain.User, error) {
	return s.repo.FindByUsername(ctx, username)
}

func (s *userService) List(ctx context.Context, offset, limit int64) ([]domain.User, int64, error) {
	users, err := s.repo.List(ctx, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	total, _ := s.repo.Count(ctx)
	return users, total, nil
}

func (s *userService) Update(ctx context.Context, u domain.User) (int64, error) {
	return s.repo.Update(ctx, u)
}

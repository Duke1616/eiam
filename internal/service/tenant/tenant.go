package tenant

import (
	"context"
	"strconv"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/role"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/casbin/casbin/v2"
	"golang.org/x/sync/errgroup"
)

// ITenantService 租户业务接口
//
//go:generate mockgen -source=./tenant.go -package=tenantmocks -destination=./mocks/tenant.mock.go -typed ITenantService
type ITenantService interface {
	// CreateTenant 创建一个租户空间
	CreateTenant(ctx context.Context, name, code, username string, userID int64) (int64, error)
	// InitPersonalTenant 为新用户初始化个人空间 (注册即拥有)
	InitPersonalTenant(ctx context.Context, userId int64, username string) (int64, error)
	// GetTenantsByUserId 查看用户属于哪些空间 (用于登录后选定或切换)
	GetTenantsByUserId(ctx context.Context, userId int64) ([]domain.Tenant, error)
	// CheckUserTenantAccess 校验用户是否有权进入该租户空间
	CheckUserTenantAccess(ctx context.Context, userId, tenantId int64) (bool, error)
	// GetAttachedTenantsWithFilter 分页查看用户所属租户
	GetAttachedTenantsWithFilter(ctx context.Context, userId, tid, offset, limit int64, keyword string) ([]domain.Tenant, int64, error)
	// List 分页查看所有租户列表
	List(ctx context.Context, offset, limit int64) ([]domain.Tenant, int64, error)
	// Update 更新租户基本信息
	Update(ctx context.Context, t domain.Tenant) error
	// Delete 删除租户 (通常为逻辑删除)
	Delete(ctx context.Context, id int64) error
	// GetByID 获取租户详情
	GetByID(ctx context.Context, id int64) (domain.Tenant, error)
	// FindMembershipsByUserIds 批量检索一组用户的入驻关联记录
	FindMembershipsByUserIds(ctx context.Context, userIds []int64) (map[int64]domain.Membership, error)
	// BatchInitPersonalTenant 批量为用户初始化个人空间
	BatchInitPersonalTenant(ctx context.Context, users []domain.User) error
	// ListMembers 获取租户下成员列表
	ListMembers(ctx context.Context, offset, limit int64, keyword string) ([]domain.User, int64, error)
	// AssignUser 分配用户到租户空间
	AssignUser(ctx context.Context, userID int64) error
}

type tenantService struct {
	repo     repository.ITenantRepository
	userRepo repository.IUserRepository
	roleSvc  role.IRoleService      // 注入角色服务：用于初始化系统固有角色
	enforcer *casbin.SyncedEnforcer // 直接操作引擎，打破循环依赖
}

func NewTenantService(r repository.ITenantRepository, userRepo repository.IUserRepository, roleSvc role.IRoleService, enforcer *casbin.SyncedEnforcer) ITenantService {
	return &tenantService{
		repo:     r,
		userRepo: userRepo,
		roleSvc:  roleSvc,
		enforcer: enforcer,
	}
}

// CreateTenant 创建租户的核心流程
func (s *tenantService) CreateTenant(ctx context.Context, name, code, username string, userID int64) (int64, error) {
	// 1. 保存租户基本信息
	tenantID, err := s.repo.Create(ctx, domain.Tenant{
		Name:   name,
		Code:   code,
		Status: 1,
	})
	if err != nil {
		return 0, err
	}

	// 2. 将创建者加入该租户
	err = s.repo.AddMembership(ctx, userID, tenantID)
	if err != nil {
		return 0, err
	}

	// 3. 自动授予 admin 角色 (直接通过 Enforcer 操作)
	_, err = s.enforcer.AddGroupingPolicy(
		domain.UserSubject(username),
		domain.RoleSubject("admin"),
		ctxutil.ContextID(tenantID).String(),
		strconv.FormatInt(time.Now().UnixMilli(), 10),
	)

	return tenantID, err
}

func (s *tenantService) InitPersonalTenant(ctx context.Context, userId int64, username string) (int64, error) {
	// 1. 初始化个人空间
	tenantID, err := s.repo.Create(ctx, domain.Tenant{
		Name:   username + "的个人空间",
		Code:   username + "-personal",
		Status: 1,
	})
	if err != nil {
		return 0, err
	}

	// 2. 建立契约
	err = s.repo.AddMembership(ctx, userId, tenantID)
	if err != nil {
		return 0, err
	}

	// 3. 自动授予 admin 权限
	_, err = s.enforcer.AddGroupingPolicy(
		domain.UserSubject(username),
		domain.RoleSubject("admin"),
		ctxutil.ContextID(tenantID).String(),
		strconv.FormatInt(time.Now().UnixMilli(), 10),
	)

	return tenantID, err
}

func (s *tenantService) BatchInitPersonalTenant(ctx context.Context, users []domain.User) error {
	if len(users) == 0 {
		return nil
	}

	// 1. 构造租户信息并批量创建
	tenants := make([]domain.Tenant, 0, len(users))
	for _, u := range users {
		tenants = append(tenants, domain.Tenant{
			Name:   u.Username + "的个人空间",
			Code:   u.Username + "-personal",
			Status: 1,
		})
	}

	savedTenants, err := s.repo.BatchCreate(ctx, tenants)
	if err != nil {
		return err
	}

	// 2. 构造 Membership 并批量插入
	memberships := make([]domain.Membership, 0, len(users))
	for i, u := range users {
		memberships = append(memberships, domain.Membership{
			UserID:   u.ID,
			TenantID: savedTenants[i].ID,
		})
	}

	if err = s.repo.BatchAddMemberships(ctx, memberships); err != nil {
		return err
	}

	// 3. 构造 Casbin 策略并批量授权
	rules := make([][]string, 0, len(users))
	for i, u := range users {
		rules = append(rules, []string{
			domain.UserSubject(u.Username),
			domain.RoleSubject("admin"),
			ctxutil.ContextID(savedTenants[i].ID).String(),
		})
	}

	_, err = s.enforcer.AddGroupingPolicies(rules)
	return err
}

func (s *tenantService) GetTenantsByUserId(ctx context.Context, userId int64) ([]domain.Tenant, error) {
	return s.repo.FindTenantsByUserId(ctx, userId)
}

func (s *tenantService) CheckUserTenantAccess(ctx context.Context, userId, tenantId int64) (bool, error) {
	// 维持原状：契约存在即代表有权进入 (Context 入场券)
	_, err := s.repo.GetMembership(ctx, tenantId, userId)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (s *tenantService) GetAttachedTenantsWithFilter(ctx context.Context, userId, tid, offset, limit int64, keyword string) ([]domain.Tenant, int64, error) {
	return s.repo.GetAttachedTenantsWithFilter(ctx, userId, tid, offset, limit, keyword)
}

func (s *tenantService) List(ctx context.Context, offset, limit int64) ([]domain.Tenant, int64, error) {
	total, err := s.repo.Count(ctx)
	if err != nil {
		return nil, 0, err
	}
	ts, err := s.repo.FindAll(ctx, offset, limit)
	return ts, total, err
}

func (s *tenantService) Update(ctx context.Context, t domain.Tenant) error {
	return s.repo.Update(ctx, t)
}

func (s *tenantService) Delete(ctx context.Context, id int64) error {
	return s.repo.Delete(ctx, id)
}

func (s *tenantService) GetByID(ctx context.Context, id int64) (domain.Tenant, error) {
	return s.repo.FindById(ctx, id)
}
func (s *tenantService) FindMembershipsByUserIds(ctx context.Context, userIds []int64) (map[int64]domain.Membership, error) {
	ms, err := s.repo.FindMembershipsByUserIds(ctx, userIds)
	if err != nil {
		return nil, err
	}

	res := make(map[int64]domain.Membership, len(ms))
	for _, m := range ms {
		res[m.UserID] = m
	}

	return res, nil
}

func (s *tenantService) ListMembers(ctx context.Context, offset, limit int64, keyword string) ([]domain.User, int64, error) {
	var (
		users []domain.User
		total int64
	)
	eg, _ := errgroup.WithContext(ctx)

	// 1. 并发查询成员详情列表 (userRepo.List 内部已通过 GORM 插件处理租户隔离)
	eg.Go(func() error {
		var err error
		users, err = s.userRepo.List(ctx, offset, limit, keyword)
		return err
	})

	// 2. 并发查询成员总数
	eg.Go(func() error {
		var err error
		total, err = s.userRepo.Count(ctx, keyword)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

func (s *tenantService) AssignUser(ctx context.Context, userID int64) error {
	tenantID := ctxutil.GetTenantID(ctx).Int64()
	return s.repo.AddMembership(ctx, userID, tenantID)
}

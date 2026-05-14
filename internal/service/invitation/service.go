package invitation

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/user"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/ecodeclub/ekit/slice"
	"github.com/google/uuid"
)

type IInvitationService interface {
	// CreateInvitation 创建邀请码
	CreateInvitation(ctx context.Context, inviterID int64, maxUses int, expireAt int64, roleCodes []string, requireApproval bool) (string, error)
	// VerifyInvitation 校验邀请码有效性并返回详细信息，可选传入 userID 校验成员资格
	VerifyInvitation(ctx context.Context, code string, userID int64) (domain.Invitation, bool, error)
	// AcceptInvitation 接受邀请，完成入驻或提交申请
	AcceptInvitation(ctx context.Context, code string, userID int64, username string) (bool, error)
	// ListInvitations 获取当前租户下所有活跃的邀请链接
	ListInvitations(ctx context.Context, offset, limit int) ([]domain.Invitation, int64, error)
	// RevokeInvitation 撤回/删除邀请链接
	RevokeInvitation(ctx context.Context, code string) error
	// BatchRevokeInvitation 批量撤回邀请码
	BatchRevokeInvitation(ctx context.Context, codes []string) error

	// ListJoinRequests 获取待审批的入驻申请
	ListJoinRequests(ctx context.Context, offset, limit int) ([]domain.JoinRequest, int64, error)
	// HandleJoinRequest 处理入驻申请 (通过/拒绝)
	HandleJoinRequest(ctx context.Context, requestID int64, approve bool) error
}

type invitationService struct {
	repo       repository.IInvitationRepository
	tenantRepo repository.ITenantRepository
	permSvc    permission.IPermissionService
	userSvc    user.IUserService
}

func NewInvitationService(repo repository.IInvitationRepository,
	tenantRepo repository.ITenantRepository,
	permSvc permission.IPermissionService,
	userSvc user.IUserService) IInvitationService {
	return &invitationService{
		repo:       repo,
		tenantRepo: tenantRepo,
		permSvc:    permSvc,
		userSvc:    userSvc,
	}
}

func (s *invitationService) CreateInvitation(ctx context.Context, inviterID int64, maxUses int, expireAt int64, roleCodes []string, requireApproval bool) (string, error) {
	code := uuid.New().String()
	inv := domain.Invitation{
		TenantID:        ctxutil.GetTenantID(ctx).Int64(),
		InviterID:       inviterID,
		Code:            code,
		RoleCodes:       roleCodes,
		MaxUses:         maxUses,
		ExpireAt:        expireAt,
		RequireApproval: requireApproval,
		Status:          domain.InvitationStatusPending,
	}

	err := s.repo.Create(ctx, inv)
	return code, err
}

func (s *invitationService) VerifyInvitation(ctx context.Context, code string, userID int64) (domain.Invitation, bool, error) {
	inv, err := s.repo.GetByCode(ctx, code)
	if err != nil {
		return domain.Invitation{}, false, errs.ErrInvitationNotFound
	}

	if !inv.CanUse() {
		return domain.Invitation{}, false, errs.ErrInvitationFull
	}

	if inv.IsExpired() {
		return domain.Invitation{}, false, errs.ErrInvitationNotFound
	}

	// 补充租户名称，方便前端展示
	t, err := s.tenantRepo.FindById(ctx, inv.TenantID)
	if err == nil {
		inv.TenantName = t.Name
	}

	// 校验当前用户是否已经是成员
	isMember := false
	if userID != 0 {
		// 注入邀请码对应的目标租户 ID
		newCtx := ctxutil.WithTenantID(ctx, inv.TenantID)
		_, err = s.tenantRepo.GetBind(newCtx, userID)
		isMember = err == nil
	}

	return inv, isMember, nil
}

func (s *invitationService) AcceptInvitation(ctx context.Context, code string, userID int64, username string) (bool, error) {
	inv, _, err := s.VerifyInvitation(ctx, code, userID)
	if err != nil {
		return false, err
	}

	// 注入正确的租户 ID，确保后续 Repo 操作在正确的租户上下文中执行
	ctx = ctxutil.WithTenantID(ctx, inv.TenantID)

	// 1. 预占用名额
	if _, err = s.repo.IncrUsedCount(ctx, code, inv.MaxUses); err != nil {
		return false, err
	}

	// 定义回滚闭包
	rollback := func() {
		_, _ = s.repo.DecrUsedCount(ctx, code)
	}

	// 2. 幂等性与成员检查
	_, err = s.tenantRepo.GetBind(ctx, userID)
	if err == nil {
		rollback()
		return false, errs.ErrAlreadyMember
	}

	// 3. 如果需要审批，则创建申请记录
	if inv.RequireApproval {
		_, err = s.repo.CreateJoinRequest(ctx, domain.JoinRequest{
			TenantID:       inv.TenantID,
			UserID:         userID,
			InvitationCode: inv.Code,
			RoleCodes:      inv.RoleCodes,
			Status:         domain.JoinRequestStatusPending,
		})
		if err != nil {
			rollback()
			return false, err
		}
		return true, nil
	}

	// 4. 执行自动入驻逻辑
	if err = s.tenantRepo.CreateBind(ctx, userID); err != nil {
		rollback()
		return false, err
	}

	// 自动授予角色
	if len(inv.RoleCodes) > 0 {
		_, _ = s.permSvc.AssignRolesToUser(ctx, []string{username}, inv.RoleCodes)
	}

	return false, nil
}

func (s *invitationService) ListInvitations(ctx context.Context, offset, limit int) ([]domain.Invitation, int64, error) {
	return s.repo.List(ctx, offset, limit)
}

func (s *invitationService) RevokeInvitation(ctx context.Context, code string) error {
	return s.repo.Delete(ctx, code)
}

func (s *invitationService) BatchRevokeInvitation(ctx context.Context, codes []string) error {
	return s.repo.BatchDelete(ctx, codes)
}

func (s *invitationService) ListJoinRequests(ctx context.Context, offset, limit int) ([]domain.JoinRequest, int64, error) {
	reqs, total, err := s.repo.ListJoinRequests(ctx, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	if len(reqs) == 0 {
		return []domain.JoinRequest{}, total, nil
	}

	// 获取用户信息
	userIds := slice.Map(reqs, func(idx int, src domain.JoinRequest) int64 {
		return src.UserID
	})
	users, err := s.userSvc.GetByIDs(ctx, userIds)
	if err != nil {
		return nil, 0, err
	}

	// 构建 map 提升查找效率
	userMap := slice.ToMap(users, func(element domain.User) int64 {
		return element.ID
	})

	// 回填用户信息
	for i := range reqs {
		if u, ok := userMap[reqs[i].UserID]; ok {
			reqs[i].Username = u.Username
			reqs[i].Nickname = u.Profile.Nickname
		}
	}

	return reqs, total, nil
}

func (s *invitationService) HandleJoinRequest(ctx context.Context, requestID int64, approve bool) error {
	req, err := s.repo.GetJoinRequestByID(ctx, requestID)
	if err != nil {
		return err
	}

	// 1. 状态校验：仅允许审批“待处理”状态的申请
	if req.Status != domain.JoinRequestStatusPending {
		return errs.ErrJoinRequestHandled
	}

	// 2. 拒绝逻辑：更新状态并归还预占用名额
	if !approve {
		if req.InvitationCode != "" {
			_, _ = s.repo.DecrUsedCount(ctx, req.InvitationCode)
		}
		return s.repo.UpdateJoinRequestStatus(ctx, requestID, domain.JoinRequestStatusRejected)
	}

	// 3. 通过逻辑：执行入驻、授权与计数更新
	return s.approveJoinRequest(ctx, req)
}

// approveJoinRequest 执行申请通过后的核心业务链
func (s *invitationService) approveJoinRequest(ctx context.Context, req domain.JoinRequest) error {
	// 1. 加入租户成员
	if err := s.tenantRepo.CreateBind(ctx, req.UserID); err != nil {
		return err
	}

	// 2. 批量授予预设角色
	if len(req.RoleCodes) > 0 {
		u, err := s.userSvc.GetById(ctx, req.UserID)
		if err == nil {
			_, _ = s.permSvc.AssignRolesToUser(ctx, []string{u.Username}, req.RoleCodes)
		}
	}

	// 3. 更新申请单状态为“已通过”
	return s.repo.UpdateJoinRequestStatus(ctx, req.ID, domain.JoinRequestStatusApproved)
}

package invitation

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/user"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

type IInvitationService interface {
	// CreateInvitation 创建邀请码
	CreateInvitation(ctx context.Context, inviterID int64, maxUses int, expireAt int64, roleCodes []string, requireApproval bool) (string, error)
	// VerifyInvitation 校验邀请码有效性
	VerifyInvitation(ctx context.Context, code string) (domain.Invitation, error)
	// AcceptInvitation 接受邀请，完成入驻或提交申请
	AcceptInvitation(ctx context.Context, code string, userID int64, username string) (bool, error)
	// ListInvitations 获取当前租户下所有活跃的邀请链接
	ListInvitations(ctx context.Context, offset, limit int) ([]domain.Invitation, int64, error)
	// RevokeInvitation 撤回/删除邀请链接
	RevokeInvitation(ctx context.Context, code string) error

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

func (s *invitationService) VerifyInvitation(ctx context.Context, code string) (domain.Invitation, error) {
	inv, err := s.repo.GetByCode(ctx, code)
	if err != nil {
		return domain.Invitation{}, errs.ErrInvitationNotFound
	}

	if !inv.CanUse() {
		return domain.Invitation{}, errs.ErrInvitationFull
	}

	if inv.IsExpired() {
		return domain.Invitation{}, errs.ErrInvitationNotFound
	}

	// 补充租户名称，方便前端展示
	t, err := s.tenantRepo.FindById(ctx, inv.TenantID)
	if err == nil {
		inv.TenantName = t.Name
	}

	return inv, nil
}

func (s *invitationService) AcceptInvitation(ctx context.Context, code string, userID int64, username string) (bool, error) {
	inv, err := s.VerifyInvitation(ctx, code)
	if err != nil {
		return false, err
	}

	// NOTE: 接受邀请时，当前用户可能未登录（无租户环境），必须从邀请码中获取 TenantID 并显式包装 Context 传给下游
	targetCtx := ctxutil.WithTenantID(ctx, inv.TenantID)

	// 1. 检查是否已经入驻
	_, err = s.tenantRepo.GetMembership(targetCtx, inv.TenantID, userID)
	if err == nil {
		return false, errs.ErrAlreadyMember
	}

	// 2. 如果需要审批，则创建申请记录
	if inv.RequireApproval {
		_, err = s.repo.CreateJoinRequest(targetCtx, domain.JoinRequest{
			TenantID:       inv.TenantID,
			UserID:         userID,
			InvitationCode: inv.Code,
			RoleCodes:      inv.RoleCodes,
			Status:         domain.JoinRequestStatusPending,
		})
		return true, err
	}

	// 3. 执行自动入驻逻辑
	err = s.tenantRepo.AddMembership(targetCtx, userID, inv.TenantID)
	if err != nil {
		return false, err
	}

	// 自动授予角色
	for _, rc := range inv.RoleCodes {
		_, _ = s.permSvc.AssignRoleToUser(ctxutil.WithTenantID(targetCtx, inv.TenantID), username, rc)
	}

	// 4. 更新使用计数
	usedCount, _ := s.repo.IncrUsedCount(targetCtx, code, inv.MaxUses)
	if inv.MaxUses > 0 && usedCount >= inv.MaxUses {
		_ = s.repo.Delete(targetCtx, code)
	}

	return false, nil
}

func (s *invitationService) ListInvitations(ctx context.Context, offset, limit int) ([]domain.Invitation, int64, error) {
	return s.repo.List(ctx, offset, limit)
}

func (s *invitationService) RevokeInvitation(ctx context.Context, code string) error {
	return s.repo.Delete(ctx, code)
}

func (s *invitationService) ListJoinRequests(ctx context.Context, offset, limit int) ([]domain.JoinRequest, int64, error) {
	reqs, total, err := s.repo.ListJoinRequests(ctx, offset, limit)
	if err != nil {
		return nil, 0, err
	}

	if len(reqs) == 0 {
		return []domain.JoinRequest{}, total, nil
	}

	// 补充用户信息
	var eg errgroup.Group
	for i := range reqs {
		idx := i
		eg.Go(func() error {
			u, err := s.userSvc.GetById(ctx, reqs[idx].UserID)
			if err == nil {
				reqs[idx].Username = u.Username
				reqs[idx].Nickname = u.Profile.Nickname
			}
			return nil
		})
	}

	_ = eg.Wait()
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

	// 2. 拒绝逻辑：直接更新状态并返回
	if !approve {
		return s.repo.UpdateJoinRequestStatus(ctx, requestID, domain.JoinRequestStatusRejected)
	}

	// 3. 通过逻辑：执行入驻、授权与计数更新
	return s.approveJoinRequest(ctx, req)
}

// approveJoinRequest 执行申请通过后的核心业务链
func (s *invitationService) approveJoinRequest(ctx context.Context, req domain.JoinRequest) error {
	// 准备目标租户上下文
	targetCtx := ctxutil.WithTenantID(ctx, req.TenantID)

	// 1. 加入租户成员
	if err := s.tenantRepo.AddMembership(targetCtx, req.UserID, req.TenantID); err != nil {
		return err
	}

	// 2. 批量授予预设角色
	if len(req.RoleCodes) > 0 {
		u, err := s.userSvc.GetById(ctx, req.UserID)
		if err == nil {
			_, _ = s.permSvc.AssignRolesToUser(targetCtx, u.Username, req.RoleCodes)
		}
	}

	// 3. 闭环邀请码逻辑（如果是通过邀请码进来的）
	if req.InvitationCode != "" {
		s.handleInvitationClosure(ctx, req.InvitationCode)
	}

	// 4. 更新申请单状态为“已通过”
	return s.repo.UpdateJoinRequestStatus(ctx, req.ID, domain.JoinRequestStatusApproved)
}

// handleInvitationClosure 处理邀请码的使用计数与自动失效逻辑
func (s *invitationService) handleInvitationClosure(ctx context.Context, code string) {
	inv, err := s.repo.GetByCode(ctx, code)
	if err != nil {
		return
	}

	targetCtx := ctxutil.WithTenantID(ctx, inv.TenantID)
	usedCount, err := s.repo.IncrUsedCount(targetCtx, code, inv.MaxUses)
	if err == nil && inv.MaxUses > 0 && usedCount >= inv.MaxUses {
		_ = s.repo.Delete(targetCtx, code)
	}
}

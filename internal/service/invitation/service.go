package invitation

import (
	"context"
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/user"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

type IInvitationService interface {
	// CreateInvitation 创建邀请码
	CreateInvitation(ctx context.Context, tenantID, inviterID int64, maxUses int, expireAt int64, roleCodes []string, requireApproval bool) (string, error)
	// VerifyInvitation 校验邀请码有效性
	VerifyInvitation(ctx context.Context, code string) (domain.Invitation, error)
	// AcceptInvitation 接受邀请，完成入驻或提交申请
	AcceptInvitation(ctx context.Context, code string, userID int64, username string) (bool, error)
	// ListInvitations 获取当前租户下所有活跃的邀请链接
	ListInvitations(ctx context.Context, tenantID int64, offset, limit int) ([]domain.Invitation, int64, error)
	// RevokeInvitation 撤回/删除邀请链接
	RevokeInvitation(ctx context.Context, tenantID int64, code string) error

	// ListJoinRequests 获取待审批的入驻申请
	ListJoinRequests(ctx context.Context, tenantID int64, offset, limit int) ([]domain.JoinRequest, int64, error)
	// HandleJoinRequest 处理入驻申请 (通过/拒绝)
	HandleJoinRequest(ctx context.Context, tenantID, requestID int64, approve bool) error
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

func (s *invitationService) CreateInvitation(ctx context.Context, tenantID, inviterID int64, maxUses int, expireAt int64, roleCodes []string, requireApproval bool) (string, error) {
	code := uuid.New().String()
	inv := domain.Invitation{
		TenantID:        tenantID,
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
		return domain.Invitation{}, domain.ErrInvitationNotFound
	}

	if !inv.CanUse() {
		return domain.Invitation{}, domain.ErrInvitationFull
	}

	if inv.IsExpired() {
		return domain.Invitation{}, domain.ErrInvitationNotFound
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

	// 1. 检查是否已经入驻
	_, err = s.tenantRepo.GetMembership(ctx, inv.TenantID, userID)
	if err == nil {
		return false, fmt.Errorf("您已是该租户成员，无需重复加入")
	}

	// 2. 如果需要审批，则创建申请记录
	if inv.RequireApproval {
		_, err = s.repo.CreateJoinRequest(ctx, domain.JoinRequest{
			TenantID:       inv.TenantID,
			UserID:         userID,
			InvitationCode: inv.Code,
			RoleCodes:      inv.RoleCodes,
			Status:         domain.JoinRequestStatusPending,
		})
		return true, err
	}

	// 3. 执行自动入驻逻辑
	err = s.tenantRepo.AddMembership(ctx, userID, inv.TenantID)
	if err != nil {
		return false, err
	}

	// 自动授予角色
	for _, rc := range inv.RoleCodes {
		_, _ = s.permSvc.AssignRoleToUser(ctxutil.WithTenantID(ctx, inv.TenantID), username, rc)
	}

	// 4. 更新使用计数
	usedCount, _ := s.repo.IncrUsedCount(ctx, code, inv.MaxUses)
	if inv.MaxUses > 0 && usedCount >= inv.MaxUses {
		_ = s.repo.Delete(ctx, inv.TenantID, code)
	}

	return false, nil
}

func (s *invitationService) ListInvitations(ctx context.Context, tenantID int64, offset, limit int) ([]domain.Invitation, int64, error) {
	return s.repo.ListByTenant(ctx, tenantID, offset, limit)
}

func (s *invitationService) RevokeInvitation(ctx context.Context, tenantID int64, code string) error {
	return s.repo.Delete(ctx, tenantID, code)
}

func (s *invitationService) ListJoinRequests(ctx context.Context, tenantID int64, offset, limit int) ([]domain.JoinRequest, int64, error) {
	reqs, total, err := s.repo.ListJoinRequests(ctx, tenantID, offset, limit)
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

func (s *invitationService) HandleJoinRequest(ctx context.Context, tenantID, requestID int64, approve bool) error {
	req, err := s.repo.GetJoinRequestByID(ctx, requestID)
	if err != nil {
		return err
	}

	if req.TenantID != tenantID {
		return fmt.Errorf("无权处理该申请")
	}

	if req.Status != domain.JoinRequestStatusPending {
		return fmt.Errorf("申请已处理")
	}

	if !approve {
		return s.repo.UpdateJoinRequestStatus(ctx, requestID, domain.JoinRequestStatusRejected)
	}

	// 执行通过逻辑
	// 1. 加入租户
	err = s.tenantRepo.AddMembership(ctx, req.UserID, tenantID)
	if err != nil {
		return err
	}

	// 2. 获取用户名并绑定角色
	u, err := s.userSvc.GetById(ctx, req.UserID)
	if err == nil {
		for _, rc := range req.RoleCodes {
			_, _ = s.permSvc.AssignRoleToUser(ctxutil.WithTenantID(ctx, tenantID), u.Username, rc)
		}
	}

	// 3. 如果是通过邀请码进来的，更新对应邀请码的计数
	if req.InvitationCode != "" {
		inv, err := s.repo.GetByCode(ctx, req.InvitationCode)
		if err == nil {
			usedCount, err := s.repo.IncrUsedCount(ctx, req.InvitationCode, inv.MaxUses)
			if err == nil && inv.MaxUses > 0 && usedCount >= inv.MaxUses {
				_ = s.repo.Delete(ctx, tenantID, req.InvitationCode)
			}
		}
	}

	// 4. 更新申请状态
	return s.repo.UpdateJoinRequestStatus(ctx, requestID, domain.JoinRequestStatusApproved)
}

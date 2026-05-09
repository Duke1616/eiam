package repository

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/Duke1616/eiam/pkg/sqlx"
	"golang.org/x/sync/errgroup"
)

type IInvitationRepository interface {
	// Create 创建邀请码记录
	Create(ctx context.Context, inv domain.Invitation) error
	// GetByCode 根据邀请码获取邀请信息
	GetByCode(ctx context.Context, code string) (domain.Invitation, error)
	// IncrUsedCount 原子增加邀请码使用次数
	IncrUsedCount(ctx context.Context, code string, maxUses int) (int, error)
	// Delete 删除邀请码（软删除）
	Delete(ctx context.Context, tenantID int64, code string) error
	// ListByTenant 分页获取租户下的邀请码列表
	ListByTenant(ctx context.Context, tenantID int64, offset, limit int) ([]domain.Invitation, int64, error)
	// UpdateStatus 更新邀请码状态
	UpdateStatus(ctx context.Context, code string, status domain.InvitationStatus) error

	// CreateJoinRequest 创建入驻申请
	CreateJoinRequest(ctx context.Context, req domain.JoinRequest) (int64, error)
	// ListJoinRequests 分页获取租户下的入驻申请
	ListJoinRequests(ctx context.Context, tenantID int64, offset, limit int) ([]domain.JoinRequest, int64, error)
	// GetJoinRequestByID 根据 ID 获取申请记录
	GetJoinRequestByID(ctx context.Context, id int64) (domain.JoinRequest, error)
	// UpdateJoinRequestStatus 更新申请状态
	UpdateJoinRequestStatus(ctx context.Context, id int64, status domain.JoinRequestStatus) error
}

type invitationRepository struct {
	dao   dao.IInvitationDAO
	cache cache.IInvitationCache
}

func NewInvitationRepository(dao dao.IInvitationDAO, cache cache.IInvitationCache) IInvitationRepository {
	return &invitationRepository{
		dao:   dao,
		cache: cache,
	}
}

func (r *invitationRepository) Create(ctx context.Context, inv domain.Invitation) error {
	_, err := r.dao.Insert(ctx, r.toDaoInvitation(inv))
	if err != nil {
		return err
	}

	return r.cache.Set(ctx, inv)
}

func (r *invitationRepository) GetByCode(ctx context.Context, code string) (domain.Invitation, error) {
	inv, err := r.dao.GetByCode(ctx, code)
	if err != nil {
		return domain.Invitation{}, err
	}

	res := r.toDomainInvitation(inv)

	// 获取实时计数
	cachedInv, err := r.cache.Get(ctx, code)
	if err == nil {
		res.UsedCount = cachedInv.UsedCount
	}

	return res, nil
}

func (r *invitationRepository) IncrUsedCount(ctx context.Context, code string, maxUses int) (int, error) {
	return r.cache.IncrUsedCount(ctx, code, maxUses)
}

func (r *invitationRepository) Delete(ctx context.Context, tenantID int64, code string) error {
	// 尝试同步计数回 DB 再删除缓存
	cached, err := r.cache.Get(ctx, code)
	if err == nil {
		_ = r.dao.UpdateUsedCount(ctx, code, cached.UsedCount)
	}

	_ = r.dao.Delete(ctx, tenantID, code)
	return r.cache.Delete(ctx, tenantID, code)
}

func (r *invitationRepository) ListByTenant(ctx context.Context, tenantID int64, offset, limit int) ([]domain.Invitation, int64, error) {
	var (
		eg    errgroup.Group
		invs  []dao.Invitation
		total int64
	)

	eg.Go(func() error {
		var err error
		invs, err = r.dao.ListByTenant(ctx, tenantID, offset, limit)
		return err
	})

	eg.Go(func() error {
		var err error
		total, err = r.dao.CountByTenant(ctx, tenantID)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, 0, err
	}

	res := make([]domain.Invitation, 0, len(invs))
	for _, inv := range invs {
		item := r.toDomainInvitation(inv)
		// 尝试从缓存回填计数
		cachedInv, err := r.cache.Get(ctx, inv.Code)
		if err == nil {
			item.UsedCount = cachedInv.UsedCount
		} else {
			item.UsedCount = inv.UsedCount
		}
		res = append(res, item)
	}
	return res, total, nil
}

func (r *invitationRepository) UpdateStatus(ctx context.Context, code string, status domain.InvitationStatus) error {
	err := r.dao.UpdateStatus(ctx, code, uint8(status))
	if err != nil {
		return err
	}

	if status == domain.InvitationStatusUsed || status == domain.InvitationStatusExpired {
		inv, err := r.dao.GetByCode(ctx, code)
		if err == nil {
			return r.cache.Delete(ctx, inv.TenantId, code)
		}
	}
	return nil
}

func (r *invitationRepository) CreateJoinRequest(ctx context.Context, req domain.JoinRequest) (int64, error) {
	return r.dao.InsertJoinRequest(ctx, r.toDaoJoinRequest(req))
}

func (r *invitationRepository) ListJoinRequests(ctx context.Context, tenantID int64, offset, limit int) ([]domain.JoinRequest, int64, error) {
	var (
		eg    errgroup.Group
		reqs  []dao.JoinRequest
		total int64
	)

	eg.Go(func() error {
		var err error
		reqs, err = r.dao.ListJoinRequests(ctx, tenantID, offset, limit)
		return err
	})

	eg.Go(func() error {
		var err error
		total, err = r.dao.CountJoinRequests(ctx, tenantID)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, 0, err
	}

	res := make([]domain.JoinRequest, 0, len(reqs))
	for _, req := range reqs {
		res = append(res, r.toDomainJoinRequest(req))
	}
	return res, total, nil
}

func (r *invitationRepository) GetJoinRequestByID(ctx context.Context, id int64) (domain.JoinRequest, error) {
	req, err := r.dao.GetJoinRequestByID(ctx, id)
	if err != nil {
		return domain.JoinRequest{}, err
	}
	return r.toDomainJoinRequest(req), nil
}

func (r *invitationRepository) UpdateJoinRequestStatus(ctx context.Context, id int64, status domain.JoinRequestStatus) error {
	return r.dao.UpdateJoinRequestStatus(ctx, id, uint8(status))
}

func (r *invitationRepository) toDomainInvitation(inv dao.Invitation) domain.Invitation {
	return domain.Invitation{
		ID:              inv.Id,
		TenantID:        inv.TenantId,
		InviterID:       inv.InviterId,
		Code:            inv.Code,
		RoleCodes:       inv.RoleCodes.Val,
		MaxUses:         inv.MaxUses,
		UsedCount:       inv.UsedCount,
		ExpireAt:        inv.ExpireAt,
		Status:          domain.InvitationStatus(inv.Status),
		RequireApproval: inv.RequireApproval,
		Ctime:           inv.Ctime,
	}
}

func (r *invitationRepository) toDaoInvitation(inv domain.Invitation) dao.Invitation {
	return dao.Invitation{
		Id:              inv.ID,
		TenantId:        inv.TenantID,
		InviterId:       inv.InviterID,
		Code:            inv.Code,
		RoleCodes:       sqlx.JSONColumn[[]string]{Val: inv.RoleCodes, Valid: true},
		MaxUses:         inv.MaxUses,
		UsedCount:       inv.UsedCount,
		ExpireAt:        inv.ExpireAt,
		Status:          uint8(inv.Status),
		RequireApproval: inv.RequireApproval,
	}
}

func (r *invitationRepository) toDomainJoinRequest(req dao.JoinRequest) domain.JoinRequest {
	return domain.JoinRequest{
		ID:             req.Id,
		TenantID:       req.TenantId,
		UserID:         req.UserId,
		InvitationCode: req.InvitationCode,
		RoleCodes:      req.RoleCodes.Val,
		Status:         domain.JoinRequestStatus(req.Status),
		Ctime:          req.Ctime,
	}
}

func (r *invitationRepository) toDaoJoinRequest(req domain.JoinRequest) dao.JoinRequest {
	return dao.JoinRequest{
		Id:             req.ID,
		TenantId:       req.TenantID,
		UserId:         req.UserID,
		InvitationCode: req.InvitationCode,
		RoleCodes:      sqlx.JSONColumn[[]string]{Val: req.RoleCodes, Valid: true},
		Status:         uint8(req.Status),
	}
}

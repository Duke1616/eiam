package invitation

import (
	"errors"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/service/invitation"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

type Handler struct {
	svc invitation.IInvitationService
	sp  session.Provider
}

func NewHandler(svc invitation.IInvitationService, sp session.Provider) *Handler {
	return &Handler{
		svc: svc,
		sp:  sp,
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
	g := server.Group("/api/invitation")
	g.GET("/verify/:code", ginx.W(h.VerifyInvitation))
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/invitation")
	g.POST("/create", ginx.B[CreateInvitationReq](h.CreateInvitation))
	g.POST("/accept", ginx.B[AcceptInvitationReq](h.AcceptInvitation))
	g.POST("/list", ginx.B[Page](h.ListInvitations))
	g.DELETE("/revoke/:code", ginx.W(h.RevokeInvitation))

	// 申请管理
	g.POST("/requests", ginx.B[Page](h.ListJoinRequests))
	g.POST("/requests/handle", ginx.B[HandleJoinRequestReq](h.HandleJoinRequest))
}

func (h *Handler) CreateInvitation(ctx *ginx.Context, req CreateInvitationReq) (ginx.Result, error) {
	sess, err := h.sp.Get(ctx)
	if err != nil {
		return ginx.Result{}, err
	}
	uid := sess.Claims().Uid

	var expireAt int64
	if req.ExpiryDays > 0 {
		expireAt = time.Now().AddDate(0, 0, req.ExpiryDays).UnixMilli()
	}

	// 注入租户 ID 到 Context
	code, err := h.svc.CreateInvitation(ctx.Request.Context(), uid, req.MaxUses, expireAt, req.RoleCodes, req.RequireApproval)
	if err != nil {
		return ErrInvitationCreateFailed, err
	}

	return ginx.Result{
		Data: map[string]string{"code": code},
	}, nil
}

func (h *Handler) VerifyInvitation(ctx *ginx.Context) (ginx.Result, error) {
	code, err := ctx.Param("code").AsString()
	if err != nil {
		return ginx.Result{}, err
	}

	// 尝试获取当前登录用户 (可选)
	var uid int64
	if sess, err := h.sp.Get(ctx); err == nil {
		uid = sess.Claims().Uid
	}

	inv, isMember, err := h.svc.VerifyInvitation(ctx.Request.Context(), code, uid)
	if err != nil {
		if errors.Is(err, errs.ErrInvitationNotFound) {
			return ErrInvitationNotFound, err
		}
		if errors.Is(err, errs.ErrInvitationFull) {
			return ErrInvitationFull, err
		}
		return ErrInvitationVerifyFailed, err
	}

	return ginx.Result{
		Data: InvitationVO{
			TenantName:      inv.TenantName,
			InviterID:       inv.InviterID,
			RoleCodes:       inv.RoleCodes,
			MaxUses:         inv.MaxUses,
			UsedCount:       inv.UsedCount,
			ExpireAt:        inv.ExpireAt,
			RequireApproval: inv.RequireApproval,
			IsMember:        isMember,
		},
	}, nil
}

func (h *Handler) AcceptInvitation(ctx *ginx.Context, req AcceptInvitationReq) (ginx.Result, error) {
	sess, err := h.sp.Get(ctx)
	if err != nil {
		return ginx.Result{}, err
	}

	uid := sess.Claims().Uid
	username, _ := sess.Get(ctx.Request.Context(), "username").AsString()

	requireApproval, err := h.svc.AcceptInvitation(ctx.Request.Context(), req.Code, uid, username)
	if err != nil {
		if errors.Is(err, errs.ErrInvitationNotFound) {
			return ErrInvitationNotFound, err
		}
		if errors.Is(err, errs.ErrInvitationFull) {
			return ErrInvitationFull, err
		}
		if errors.Is(err, errs.ErrAlreadyMember) {
			return ErrAlreadyMember, err
		}
		return ErrInvitationAcceptFailed, err
	}

	msg := "成功加入租户"
	if requireApproval {
		msg = "加入申请已提交，请等待管理员审批"
	}

	return ginx.Result{
		Msg:  msg,
		Data: map[string]bool{"require_approval": requireApproval},
	}, nil
}

func (h *Handler) ListInvitations(ctx *ginx.Context, req Page) (ginx.Result, error) {
	invitations, total, err := h.svc.ListInvitations(ctx.Request.Context(), req.Offset, req.Limit)
	if err != nil {
		return ErrInvitationListFailed, err
	}

	return ginx.Result{
		Data: RetrieveInvitations{
			Total: total,
			Invitations: lo.Map(invitations, func(inv domain.Invitation, _ int) InvitationVO {
				return InvitationVO{
					Code:            inv.Code,
					TenantName:      inv.TenantName,
					InviterID:       inv.InviterID,
					RoleCodes:       inv.RoleCodes,
					MaxUses:         inv.MaxUses,
					UsedCount:       inv.UsedCount,
					ExpireAt:        inv.ExpireAt,
					RequireApproval: inv.RequireApproval,
				}
			}),
		},
	}, nil
}

func (h *Handler) RevokeInvitation(ctx *ginx.Context) (ginx.Result, error) {
	code, err := ctx.Param("code").AsString()
	if err != nil {
		return ginx.Result{}, err
	}

	err = h.svc.RevokeInvitation(ctx.Request.Context(), code)
	if err != nil {
		return ErrInvitationRevokeFailed, err
	}

	return ginx.Result{
		Msg: "撤回成功",
	}, nil
}

func (h *Handler) ListJoinRequests(ctx *ginx.Context, req Page) (ginx.Result, error) {
	reqs, total, err := h.svc.ListJoinRequests(ctx.Request.Context(), req.Offset, req.Limit)
	if err != nil {
		return ErrJoinRequestListFailed, err
	}

	return ginx.Result{
		Data: RetrieveJoinRequests{
			Total: total,
			Requests: lo.Map(reqs, func(r domain.JoinRequest, _ int) JoinRequestVO {
				return JoinRequestVO{
					ID:             r.ID,
					UserID:         r.UserID,
					Username:       r.Username,
					Nickname:       r.Nickname,
					InvitationCode: r.InvitationCode,
					RoleCodes:      r.RoleCodes,
					Ctime:          r.Ctime,
				}
			}),
		},
	}, nil
}

func (h *Handler) HandleJoinRequest(ctx *ginx.Context, req HandleJoinRequestReq) (ginx.Result, error) {
	if err := h.svc.HandleJoinRequest(ctx.Request.Context(), req.ID, req.Approve); err != nil {
		if errors.Is(err, errs.ErrUnauthorizedHandle) {
			return ErrUnauthorized, err
		}
		if errors.Is(err, errs.ErrJoinRequestHandled) {
			return ErrJoinRequestHandled, err
		}
		return ErrJoinRequestHandleFailed, err
	}

	return ginx.Result{
		Msg: "处理成功",
	}, nil
}

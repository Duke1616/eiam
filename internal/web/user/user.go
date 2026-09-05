package user

import (
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gotomicro/ego/core/elog"
	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"
)

func (h *Handler) Profile(ctx *ginx.Context, sess session.Session) (ginx.Result, error) {
	uid := sess.Claims().Uid
	var (
		eg      errgroup.Group
		u       domain.User
		tenants []domain.Tenant
	)

	// 并发获取用户信息和租户列表
	eg.Go(func() error {
		var err error
		u, err = h.userSvc.GetById(ctx.Request.Context(), uid)
		return err
	})

	eg.Go(func() error {
		var err error
		tenants, err = h.tenantSvc.GetTenantsByUserId(ctx.Request.Context(), uid)
		return err
	})

	if err := eg.Wait(); err != nil {
		return ErrUserNotFound, err
	}

	tenantID, _ := sess.Get(ctx.Request.Context(), "tenant_id").AsInt64()
	roles, _ := h.permSvc.GetRolesForUser(ctx.Request.Context(), u.Username)
	permissions, _ := h.permSvc.GetAuthorizedCodes(ctx.Request.Context(), u.Username)

	return ginx.Result{
		Data: RetrieveUser{
			User:             ToUserVO(u),
			Tenants:          ToTenantVOs(tenants),
			CurrentTenantID:  tenantID,
			MustSelectTenant: tenantID <= 0 && len(tenants) > 1,
			IsAdmin:          lo.Contains(roles, "admin"),
			Permissions:      permissions,
		},
	}, nil
}

func (h *Handler) Create(ctx *ginx.Context, req SignupRequest) (ginx.Result, error) {
	id, err := h.userSvc.Signup(ctx.Request.Context(), req.ToDomain())
	if err != nil {
		return ErrSignupFailed, err
	}

	tid := ctxutil.GetTenantID(ctx).Int64()
	if tid > 0 {
		if err = h.tenantSvc.AssignUser(ctx.Request.Context(), id); err != nil {
			h.logger.Error("自动加入企业空间失败",
				elog.Int64("uid", id),
				elog.Int64("tid", tid),
				elog.FieldErr(err),
			)
		}
	}

	return ginx.Result{
		Data: id,
		Msg:  "用户主体创建成功",
	}, nil
}

func (h *Handler) UpdatePassword(ctx *ginx.Context, req UpdatePasswordRequest, sess session.Session) (ginx.Result, error) {
	if req.NewPassword != req.ConfirmPassword {
		return ErrPasswordMismatch, nil
	}

	err := h.userSvc.UpdatePassword(ctx.Request.Context(), sess.Claims().Uid, req.OldPassword, req.NewPassword)
	if err != nil {
		return ErrUnauthorized, err
	}

	return ginx.Result{Msg: "密码修改成功"}, nil
}

func (h *Handler) List(ctx *ginx.Context, req ListUserRequest) (ginx.Result, error) {
	users, total, err := h.fetchUsers(ctx, req)
	if err != nil {
		return ginx.Result{}, err
	}

	currentTid := ctxutil.GetTenantID(ctx).Int64()
	if currentTid != ctxutil.SystemTenantID {
		return ginx.Result{
			Data: RetrieveUsers[User]{
				Total: total,
				Users: toUserVOs(users),
			},
		}, nil
	}

	// 系统空间：装饰多租户成员属性
	userIDs := lo.Map(users, func(u domain.User, _ int) int64 { return u.ID })
	memberMap, _ := h.tenantSvc.CheckUsersInTenant(ctx.Request.Context(), userIDs)

	return ginx.Result{
		Data: RetrieveUsers[UserMemberVO]{
			Total: total,
			Users: toUserMemberVOs(users, memberMap),
		},
	}, nil
}

func (h *Handler) Update(ctx *ginx.Context, req UpdateUserReq) (ginx.Result, error) {
	_, err := h.userSvc.Update(ctx.Request.Context(), req.ToDomain())
	if err != nil {
		return ErrUserUpdateFailed, err
	}
	return ginx.Result{Msg: "更新用户信息成功"}, nil
}

func (h *Handler) Detail(ctx *ginx.Context) (ginx.Result, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()

	u, err := h.resolveUser(ctx)
	if err != nil {
		return ErrUserNotFound, err
	}

	isMember, err := h.tenantSvc.CheckUserTenantAccess(ctx.Request.Context(), u.ID)
	if err != nil {
		return ginx.Result{}, err
	}

	return ginx.Result{
		Data: UserMemberVO{
			User:          ToUserVO(u),
			IsMember:      &isMember,
			IsSystemSpace: tid == ctxutil.SystemTenantID,
		},
	}, nil
}

func (h *Handler) Delete(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrUserNotFound, err
	}

	err = h.userSvc.Delete(ctx.Request.Context(), id)
	if err != nil {
		return ErrUserDeleteFailed, err
	}

	return ginx.Result{Msg: "删除用户成功"}, nil
}

func (h *Handler) BatchDelete(ctx *ginx.Context, req BatchDeleteReq) (ginx.Result, error) {
	if _, err := h.userSvc.BatchDelete(ctx.Request.Context(), req.IDs); err != nil {
		return ErrUserDeleteFailed, err
	}

	return ginx.Result{Msg: "批量删除用户成功"}, nil
}

func (h *Handler) ListAttachedRole(ctx *ginx.Context, req ListRoleUsersRequest) (ginx.Result, error) {
	users, total, err := h.userSvc.GetAttachedUsersWithFilter(ctx.Request.Context(), req.RoleCode, req.Offset, req.Limit, req.Keyword)
	if err != nil {
		return ErrUserListFailed, err
	}

	return ginx.Result{
		Data: RetrieveUsers[User]{
			Total: total,
			Users: lo.Map(users, func(src domain.User, _ int) User {
				return ToUserVO(src)
			}),
		},
	}, nil
}

// ----------- 内部辅助函数 --------------

func (h *Handler) fetchUsers(ctx *ginx.Context, req ListUserRequest) ([]domain.User, int64, error) {
	if req.Usernames != nil {
		users, err := h.userSvc.GetByUsernames(ctx, req.Usernames)
		if err != nil {
			return nil, 0, err
		}
		return users, int64(len(users)), nil
	}

	return h.userSvc.List(ctx.Request.Context(), req.Offset, req.Limit, req.Keyword)
}

func (h *Handler) resolveUser(ctx *ginx.Context) (domain.User, error) {
	if id, err := ctx.Query("id").AsInt64(); err == nil && id != 0 {
		return h.userSvc.GetById(ctx.Request.Context(), id)
	}

	if username, err := ctx.Query("username").AsString(); err == nil && username != "" {
		return h.userSvc.GetByUsername(ctx.Request.Context(), username)
	}

	return domain.User{}, fmt.Errorf("未找到该用户信息")
}

func toUserVOs(users []domain.User) []User {
	return lo.Map(users, func(u domain.User, _ int) User {
		return ToUserVO(u)
	})
}

func toUserMemberVOs(users []domain.User, memberMap map[int64]bool) []UserMemberVO {
	return lo.Map(users, func(u domain.User, _ int) UserMemberVO {
		isMember := memberMap[u.ID]
		return UserMemberVO{
			User:     ToUserVO(u),
			IsMember: &isMember,
		}
	})
}

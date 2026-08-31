package user

import (
	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/ecodeclub/ginx"
	"github.com/samber/lo"
)

func (h *Handler) SearchLdapUser(ctx *ginx.Context, req SearchLdapUser) (ginx.Result, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()
	users, total, err := h.ldapSvc.SearchCacheUserWithPager(ctx.Request.Context(), tid, req.Keywords, req.Offset, req.Limit)
	if err != nil {
		return ErrLdapSearchFailed, err
	}

	usernames := lo.Map(users, func(src domain.User, _ int) string {
		return src.Username
	})

	existMap, err := h.userSvc.CheckUsersExist(ctx.Request.Context(), usernames)
	if err != nil {
		existMap = make(map[string]bool)
	}

	return ginx.Result{
		Data: LdapUserList{
			Total: int64(total),
			Users: lo.Map(users, func(src domain.User, _ int) LdapSyncUser {
				return LdapSyncUser{
					User:     ToUserVO(src),
					IsSynced: existMap[src.Username],
				}
			}),
		},
	}, nil
}

func (h *Handler) SyncLdapUser(ctx *ginx.Context, req SyncLdapUserReq) (ginx.Result, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()
	users := lo.Map(req.Users, func(src User, _ int) domain.User {
		return src.ToDomain()
	})

	err := h.ldapSvc.Sync(ctx.Request.Context(), tid, users)
	if err != nil {
		return ErrLdapSyncFailed, err
	}

	return ginx.Result{Msg: "同步 LDAP 用户成功"}, nil
}

func (h *Handler) LdapRefreshCache(ctx *ginx.Context) (ginx.Result, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()
	err := h.ldapSvc.RefreshCacheUserWithPager(ctx.Request.Context(), tid)
	if err != nil {
		return ErrLdapRefreshFailed, err
	}

	return ginx.Result{Msg: "刷新 LDAP 缓存成功"}, nil
}

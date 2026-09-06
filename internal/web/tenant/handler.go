package tenant

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Duke1616/eiam/internal/domain"
	permsvc "github.com/Duke1616/eiam/internal/service/permission"
	"github.com/Duke1616/eiam/internal/service/tenant"
	"github.com/Duke1616/eiam/pkg/contract/model"
	"github.com/Duke1616/eiam/pkg/contract/permission"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/Duke1616/eiam/pkg/web/middleware"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
	"github.com/samber/lo"
)

type Handler struct {
	capability.IRegistry
	svc     tenant.ITenantService
	permSvc permsvc.IPermissionService
	logger  *elog.Component
}

func NewHandler(svc tenant.ITenantService, permSvc permsvc.IPermissionService) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("iam", "tenant", "租户管理").
			DefaultScope(capability.ScopeSystem),
		svc:     svc,
		permSvc: permSvc,
		logger:  elog.DefaultLogger.With(elog.FieldComponent("tenant.handler")),
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {}

func (h *Handler) IdentityRoutes(server *gin.Engine) {
	g := server.Group("/api/tenant")

	// 基础身份能力：查询我隶属的租户列表 (免权限同步，自动注入会话)
	g.GET("/list/mine", h.Define("查询我的租户列表", "view_mine").
		Scope(capability.ScopeTenant).NoSync().
		Bind(ginx.S(h.ListMyTenants)),
	)

	// 核心会话能力：租户工作空间上下文动态切换 (使用 ginx.BS 自动绑定请求体与会话)
	// 租户切换仅为会话视角路由，不产生业务数据变更，声明 NoAudit 且不记认证审计，保持审计流水纯净
	g.POST("/switch", h.Define("切换租户空间", "switch").
		Scope(capability.ScopeTenant).NoSync().NoAudit().
		Route(capability.WithCrossTenant()).
		Handle(ginx.BS[SwitchTenantReq](h.SwitchTenant)),
	)
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/tenant")

	// 1. 租户生命周期管理 (系统级治理)
	g.POST("/create", h.Define("创建租户空间", "add").
		Bind(ginx.BS[CreateTenantReq](h.CreateTenant)),
	)
	g.POST("/list", h.Define("全量租户列表", "view").
		Bind(ginx.B[ListTenantReq](h.ListTenants)),
	)
	g.POST("/list/by-ids", h.Define("批量查询租户", "view_by_ids").
		Bind(ginx.B[ListTenantsByIDsReq](h.ListTenantsByIDs)),
	)
	g.POST("/update", h.Define("修改租户信息", "edit").
		Needs(permission.Tenant.Get).
		Bind(ginx.B[UpdateTenantReq](h.UpdateTenant)),
	)
	g.DELETE("/delete/:id", h.Define("删除租户空间", "delete").
		Bind(ginx.W(h.DeleteTenant)),
	)
	g.POST("/batch_delete", h.Define("批量删除租户", "batch_delete").
		Bind(ginx.B[BatchDeleteTenantReq](h.BatchDeleteTenants)),
	)
	g.GET("/detail/:id", h.Define("查看租户详情", "get").
		Bind(ginx.W(h.Detail)),
	)

	// 2. 租户成员与关联治理 (使用 BTO / BSTO 原语自动注入跨租户覆写支持)
	g.POST("/members", h.Define("查看租户成员", "view_members").
		Scope(capability.ScopeTenant).
		Bind(middleware.BTO[ListMembersReq](h.ListMembers)),
	)
	g.POST("/assign", h.Define("分配租户成员", "assign").
		Needs(permission.User.View).
		Bind(middleware.BTO[AssignUserReq](h.AssignUser)),
	)
	g.POST("/unassign", h.Define("移除租户成员", "unassign").
		Bind(middleware.BSTO[RemoveMemberReq](h.RemoveMember)),
	)
	g.POST("/batch_assign", h.Define("批量分配租户成员", "batch_assign").
		Needs(permission.User.View).
		Bind(middleware.BTO[BatchAssignTenantsReq](h.BatchAssignTenants)),
	)
	g.POST("/batch_unassign", h.Define("批量移除租户成员", "batch_unassign").
		Bind(middleware.BSTO[BatchUnassignTenantsReq](h.BatchUnassignTenants)),
	)
	g.POST("/list/attached/user", h.For(model.User).Define("查询用户所属租户", "view_user_tenants").
		Scope(capability.ScopeTenant).
		Bind(middleware.BSTO[ListUserTenantsReq](h.GetTenantsByUserId)),
	)
}

// SwitchTenant 实现租户工作空间动态切换 (使用 ginx.BS 显式绑定请求体与会话，优雅闭环安全审计)
func (h *Handler) SwitchTenant(ctx *ginx.Context, req SwitchTenantReq, sess session.Session) (res ginx.Result, err error) {
	targetTid := req.TenantID
	if targetTid <= 0 {
		return ErrTenantAccess, fmt.Errorf("未指定目标租户空间")
	}

	uid := sess.Claims().Uid
	username, _ := sess.Get(ctx.Context, "username").AsString()

	// 1. 安全校验：确认该用户是否隶属于目标租户 (必须绑定目标租户上下文以供底层 DAO 判定)
	targetCtx := ctxutil.WithTenantID(ctx.Request.Context(), targetTid)
	hasAccess, accessErr := h.svc.CheckUserTenantAccess(targetCtx, uid)
	if accessErr != nil || !hasAccess {
		err = lo.CoalesceOrEmpty(accessErr, fmt.Errorf("无权访问目标租户空间"))
		return ErrTenantAccess, err
	}

	// 2. 显式销毁旧 Session，防范令牌重放
	_ = sess.Destroy(ctx.Context)

	// 3. 重签正式 Session 并注入新租户身份
	_, sErr := session.NewSessionBuilder(ctx, uid).
		SetJwtData(map[string]string{
			"tenant_id": strconv.FormatInt(targetTid, 10),
			"username":  username,
		}).
		SetSessData(map[string]any{
			"tenant_id": targetTid,
			"username":  username,
		}).
		Build()

	if sErr != nil {
		err = sErr
		return ErrTenantSwitch, err
	}

	// 4. 记录用户最近一次活跃租户，供后续免选直达
	_ = h.svc.UpdateLastActiveTenant(ctx.Request.Context(), uid, targetTid)

	return ginx.Result{Msg: "成功切换至新租户空间"}, nil
}

// CreateTenant 用户创建企业/工作空间
func (h *Handler) CreateTenant(ctx *ginx.Context, req CreateTenantReq, sess session.Session) (ginx.Result, error) {
	username, ok := sess.Claims().Data["username"]
	if !ok {
		return ErrUnauthenticated, fmt.Errorf("session 中缺失用户名信息")
	}

	tenantId, err := h.svc.CreateTenant(ctx.Context, req.Name, req.Code, username, sess.Claims().Uid)
	if err != nil {
		return ErrTenantCreate, err
	}

	// 为创建者自动赋予初始 admin 角色
	newCtx := ctxutil.WithTenantID(ctx.Context, tenantId)
	if _, aErr := h.permSvc.AssignRoleToUser(newCtx, username, "admin"); aErr != nil {
		h.logger.Error("租户创建者授权初始角色失败", elog.FieldErr(aErr), elog.Int64("tenantId", tenantId), elog.String("username", username))
	}

	return ginx.Result{
		Data: tenantId,
		Msg:  "企业租户空间创建成功",
	}, nil
}

// ListMyTenants 查询当前用户隶属的全部租户 (利用 ginx.S 自动注入会话)
func (h *Handler) ListMyTenants(ctx *ginx.Context, sess session.Session) (ginx.Result, error) {
	uid := sess.Claims().Uid
	tenants, err := h.svc.GetTenantsByUserId(ctx.Context, uid)
	if err != nil {
		return ErrTenantList, err
	}

	return ginx.Result{Data: ToTenantVOs(tenants)}, nil
}

func (h *Handler) ListTenants(ctx *ginx.Context, req ListTenantReq) (ginx.Result, error) {
	if err := h.ensureSystemTenant(ctx); err != nil {
		return ErrTenantAccess, err
	}

	tenants, total, err := h.svc.List(ctx.Context, req.Offset, req.Limit, req.Keyword)
	if err != nil {
		return ErrTenantList, err
	}

	return ginx.Result{
		Data: ListTenantRes{
			Total:   total,
			Tenants: ToTenantVOs(tenants),
		},
	}, nil
}

func (h *Handler) ListTenantsByIDs(ctx *ginx.Context, req ListTenantsByIDsReq) (ginx.Result, error) {
	tenants, err := h.svc.ListByIDs(ctx.Context, req.IDs)
	if err != nil {
		return ErrTenantList, err
	}

	return ginx.Result{
		Data: ListTenantsByIDsRes{Tenants: ToTenantVOs(tenants)},
	}, nil
}

func (h *Handler) Detail(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrTenantGet, err
	}

	currentTid := ctxutil.GetTenantID(ctx.Context).Int64()
	if currentTid != ctxutil.SystemTenantID && currentTid != id {
		return ErrTenantAccess, fmt.Errorf("无权查看该租户详情")
	}

	t, err := h.svc.GetByID(ctx.Context, id)
	if err != nil {
		return ErrTenantGet, err
	}

	return ginx.Result{Data: ToTenantVO(t)}, nil
}

func (h *Handler) UpdateTenant(ctx *ginx.Context, req UpdateTenantReq) (ginx.Result, error) {
	currentTid := ctxutil.GetTenantID(ctx.Context).Int64()
	if currentTid != ctxutil.SystemTenantID && currentTid != req.ID {
		return ErrTenantAccess, fmt.Errorf("无权更新目标租户空间")
	}

	err := h.svc.Update(ctx.Context, domain.Tenant{
		ID:     req.ID,
		Name:   req.Name,
		Code:   req.Code,
		Domain: req.Domain,
		Status: req.Status,
	})
	if err != nil {
		return ErrTenantUpdate, err
	}

	return ginx.Result{Msg: "更新租户空间信息成功"}, nil
}

func (h *Handler) DeleteTenant(ctx *ginx.Context) (ginx.Result, error) {
	id, err := ctx.Param("id").AsInt64()
	if err != nil {
		return ErrTenantDelete, err
	}

	if err = h.ensureSystemTenant(ctx); err != nil {
		return ErrTenantAccess, err
	}

	if err = h.svc.Delete(ctx.Context, id); err != nil {
		return ErrTenantDelete, err
	}

	return ginx.Result{Msg: "删除租户空间成功"}, nil
}

func (h *Handler) BatchDeleteTenants(ctx *ginx.Context, req BatchDeleteTenantReq) (ginx.Result, error) {
	if err := h.ensureSystemTenant(ctx); err != nil {
		return ErrTenantAccess, err
	}

	if err := h.svc.BatchDelete(ctx.Context, req.IDs); err != nil {
		return ErrTenantDelete, err
	}

	return ginx.Result{Msg: "批量删除租户空间成功"}, nil
}

func (h *Handler) ListMembers(ctx *ginx.Context, req ListMembersReq) (ginx.Result, error) {
	users, total, err := h.svc.ListMembers(ctx.Context, req.Offset, req.Limit, req.Keyword)
	if err != nil {
		return ErrTenantGet, err
	}

	return ginx.Result{
		Data: ListMembersRes{
			Total: total,
			Members: lo.Map(users, func(u domain.User, _ int) MemberVO {
				return MemberVO{
					ID:          u.ID,
					Username:    u.Username,
					Nickname:    u.Profile.Nickname,
					Avatar:      u.Profile.Avatar,
					Email:       u.Email,
					Status:      int(u.Status),
					JobTitle:    u.Profile.JobTitle,
					LastLoginAt: u.LastLoginAt,
					Ctime:       u.Ctime,
				}
			}),
		},
	}, nil
}

func (h *Handler) AssignUser(ctx *ginx.Context, req AssignUserReq) (ginx.Result, error) {
	if err := h.svc.AssignUser(ctx.Context, req.UserID); err != nil {
		return ErrTenantUpdate, err
	}
	return ginx.Result{Msg: "分配用户到租户成功"}, nil
}

func (h *Handler) RemoveMember(ctx *ginx.Context, req RemoveMemberReq, sess session.Session) (ginx.Result, error) {
	currentUID := sess.Claims().Uid

	// 防自锁：禁止管理员将自身账号从当前租户中移除
	if req.UserID == currentUID {
		h.logger.Warn("拦截危险操作: 尝试将当前登录账号从当前空间移除", elog.Int64("uid", currentUID))
		return ErrCannotRemoveSelf, fmt.Errorf("禁止将当前登录账号从当前租户空间中移除")
	}

	if err := h.svc.RemoveMember(ctx.Context, req.UserID); err != nil {
		if strings.Contains(err.Error(), "admin") {
			return ErrCannotRemoveSuperAdmin, err
		}
		return ErrTenantRemoveMember, err
	}
	return ginx.Result{Msg: "成功将用户从租户空间移除"}, nil
}

func (h *Handler) BatchAssignTenants(ctx *ginx.Context, req BatchAssignTenantsReq) (ginx.Result, error) {
	if res, err := h.validateBatchDimension(ctx, req.UserIDs, req.TenantIDs); err != nil {
		return res, err
	}

	if err := h.svc.BatchAssignTenants(ctx.Context, req.UserIDs, req.TenantIDs); err != nil {
		return ErrTenantUpdate, err
	}
	return ginx.Result{Msg: "批量分配租户成功"}, nil
}

func (h *Handler) BatchUnassignTenants(ctx *ginx.Context, req BatchUnassignTenantsReq, sess session.Session) (ginx.Result, error) {
	if res, err := h.validateBatchDimension(ctx, req.UserIDs, req.TenantIDs); err != nil {
		return res, err
	}

	currentUID := sess.Claims().Uid
	for _, uid := range req.UserIDs {
		// 禁止取消当前登录账号的租户关联
		if uid == currentUID {
			return ErrCannotRemoveSelf, fmt.Errorf("禁止取消当前登录账号的租户关联")
		}
	}

	if err := h.svc.BatchUnassignTenants(ctx.Context, req.UserIDs, req.TenantIDs); err != nil {
		if strings.Contains(err.Error(), "admin") {
			return ErrCannotRemoveSuperAdmin, err
		}
		return ErrTenantRemoveMember, err
	}
	return ginx.Result{Msg: "成功取消用户与选定租户的关联记录"}, nil
}

func (h *Handler) BatchRemoveMembers(ctx *ginx.Context, req BatchRemoveMembersReq) (ginx.Result, error) {
	if err := h.svc.BatchRemoveMembers(ctx.Context, req.UserIDs); err != nil {
		if strings.Contains(err.Error(), "admin") {
			return ErrCannotRemoveSuperAdmin, err
		}
		return ErrTenantRemoveMember, err
	}
	return ginx.Result{Msg: "成功将选定用户从租户空间移除"}, nil
}

func (h *Handler) GetTenantsByUserId(ctx *ginx.Context, req ListUserTenantsReq, sess session.Session) (ginx.Result, error) {
	tid := ctxutil.GetTenantID(ctx).Int64()
	tenants, total, err := h.svc.GetAttachedTenantsWithFilter(ctx.Context, req.UserID, tid, req.Offset, req.Limit, req.Keyword)
	if err != nil {
		return ErrTenantList, err
	}

	return ginx.Result{
		Data: ListTenantRes{
			Total:   total,
			Tenants: ToTenantVOs(tenants),
		},
	}, nil
}

// ==========================================
// 辅助与私有安全断言工具
// ==========================================

// ensureSystemTenant 确保当前操作处于系统管理员上下文
func (h *Handler) ensureSystemTenant(ctx *ginx.Context) error {
	if ctxutil.GetTenantID(ctx.Context).Int64() != ctxutil.SystemTenantID {
		return fmt.Errorf("非系统管理员禁止执行此项操作")
	}
	return nil
}

// validateBatchDimension 校验批量维度的合法性并防范跨租户越权
func (h *Handler) validateBatchDimension(ctx *ginx.Context, userIDs, tenantIDs []int64) (ginx.Result, error) {
	if len(userIDs) > 1 && len(tenantIDs) > 1 {
		return ErrTenantDimensionInvalid, fmt.Errorf("仅支持单维度批量操作")
	}

	originTid := ctxutil.GetOriginTenantID(ctx.Context).Int64()
	currentTid := ctxutil.GetTenantID(ctx.Context).Int64()
	if originTid != ctxutil.SystemTenantID && lo.SomeBy(tenantIDs, func(tid int64) bool { return tid != currentTid }) {
		return ErrTenantAccess, fmt.Errorf("检测到跨租户越权操作，非系统管理员只能操作当前租户的成员")
	}
	return ginx.Result{}, nil
}

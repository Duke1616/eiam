package user

import (
	"fmt"
	"strconv"

	"github.com/Duke1616/eiam/internal/domain"
	usersvc "github.com/Duke1616/eiam/internal/service/user"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc usersvc.IUserService
	sp  session.Provider
}

func NewUserHandler(svc usersvc.IUserService, sp session.Provider) *Handler {
	return &Handler{svc: svc, sp: sp}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
	g := server.Group("/api/user")
	g.POST("/signup", ginx.B[SignupRequest](h.Signup))
	g.POST("/ldap/login", ginx.B[LoginLdapRequest](h.LoginLdap))
	g.POST("/system/login", ginx.B[LoginSystemRequest](h.LoginSystem))
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/user")
	g.GET("/profile", ginx.W(h.Profile))
	g.POST("/logout", ginx.W(h.Logout))
}

func (h *Handler) Signup(ctx *ginx.Context, req SignupRequest) (ginx.Result, error) {
	if req.Password != req.ConfirmPassword {
		return ErrPasswordMismatch, nil
	}

	id, err := h.svc.Signup(ctx.Request.Context(), req.ToDomain())
	if err != nil {
		return ErrSignupFailed, err
	}

	return ginx.Result{Data: id}, nil
}

func (h *Handler) LoginLdap(ctx *ginx.Context, req LoginLdapRequest) (ginx.Result, error) {
	result, err := h.svc.Login(ctx.Request.Context(), "ldap", req.Username, req.Password)
	if err != nil {
		return ErrUnauthorized, err
	}

	return h.handleLoginResult(ctx, result)
}

func (h *Handler) LoginSystem(ctx *ginx.Context, req LoginSystemRequest) (ginx.Result, error) {
	result, err := h.svc.Login(ctx.Request.Context(), "local", req.Username, req.Password)
	if err != nil {
		return ErrUnauthorized, err
	}

	return h.handleLoginResult(ctx, result)
}

// handleLoginResult 统一处理登录后的路由决策
func (h *Handler) handleLoginResult(ctx *ginx.Context, result domain.LoginResult) (ginx.Result, error) {
	if err := h.issueSession(ctx, result.User.ID, result.User.Username, result.TenantID); err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{
		Msg: fmt.Sprintf("登录成功，欢迎回来：%s", result.User.Username),
		Data: RetrieveUser{
			User:    ToUserVO(result.User),
			Tenants: ToTenantVOs(result.Tenants),
		},
	}, nil
}


func (h *Handler) Profile(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil || sess == nil {
		return ErrUnauthenticated, err
	}

	rawUid, err := sess.Get(ctx.Request.Context(), "uid").Int64()
	if err != nil {
		return ErrSessionInvalid, err
	}

	tenantID, _ := strconv.ParseInt(ctx.GetString("tenant_id"), 10, 64)
	newCtx := ctxutil.WithTenantID(ctx.Request.Context(), tenantID)

	u, err := h.svc.GetById(newCtx, rawUid)
	if err != nil {
		return ErrUserNotFound, err
	}

	return ginx.Result{Data: ToUserVO(u)}, nil
}

func (h *Handler) Logout(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil || sess == nil {
		return ginx.Result{Msg: "已退出登录"}, nil
	}

	if err = sess.Destroy(ctx.Request.Context()); err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{Msg: "退出登录成功"}, nil
}

// issueSession 统一颁发（或刷新）JWT，tenantID=0 代表临时凭证，等待选择
func (h *Handler) issueSession(ctx *ginx.Context, uid int64, username string, tenantID int64) error {
	jwtData := map[string]string{
		"tenant_id": strconv.FormatInt(tenantID, 10),
	}

	_, err := session.NewSessionBuilder(ctx, uid).
		SetJwtData(jwtData).
		SetSessData(map[string]any{"username": username}).
		Build()

	return err
}

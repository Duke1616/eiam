package user

import (
	"fmt"
	"strconv"

	"github.com/Duke1616/eiam/internal/domain"
	usersvc "github.com/Duke1616/eiam/internal/service/user"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc usersvc.IUserService
	sp  session.Provider
}

func NewUserHandler(svc usersvc.IUserService, sp session.Provider) *Handler {
	return &Handler{
		svc: svc,
		sp:  sp,
	}
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

// Signup 账号注册
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

// LoginLdap 专用 LDAP 登录处理函数
func (h *Handler) LoginLdap(ctx *ginx.Context, req LoginLdapRequest) (ginx.Result, error) {
	u, err := h.svc.Login(ctx.Request.Context(), "ldap", req.Username, req.Password)
	if err != nil {
		return ErrUnauthorized, err
	}

	return h.setupSession(ctx, u)
}

// LoginSystem 专用系统本地账密登录处理函数
func (h *Handler) LoginSystem(ctx *ginx.Context, req LoginSystemRequest) (ginx.Result, error) {
	u, err := h.svc.Login(ctx.Request.Context(), "local", req.Username, req.Password)
	if err != nil {
		return ErrUnauthorized, err
	}

	return h.setupSession(ctx, u)
}

// setupSession 参照 webook 模式，使用 SessionBuilder 构建完整的身份会话
func (h *Handler) setupSession(ctx *ginx.Context, u domain.User) (ginx.Result, error) {
	// 1. 构建 JWT 数据：租户 ID 必须放入 Claim
	jwtData := map[string]string{
		"tenant_id": strconv.FormatInt(u.TenantID, 10),
	}

	// 2. 构建 Session 存储数据 (Redis 等)
	sessData := map[string]any{
		"username": u.Username,
	}

	// 3. 构建并下发 Session，这会自动重置客户端的无效 Token/Cookie
	_, err := session.NewSessionBuilder(ctx, u.ID).
		SetJwtData(jwtData).
		SetSessData(sessData).
		Build()
	
	if err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{
		Msg:  fmt.Sprintf("登录成功，欢迎回来：%s", u.Username),
		Data: ToUserVO(u),
	}, nil
}

// Logout 退出登录
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

// Profile 获取资料
func (h *Handler) Profile(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil || sess == nil {
		return ErrUnauthenticated, err
	}

	rawUid, err := sess.Get(ctx.Request.Context(), "uid").Int64()
	if err != nil {
		return ErrSessionInvalid, err
	}

	u, err := h.svc.GetById(ctx.Request.Context(), rawUid)
	if err != nil {
		return ErrUserNotFound, err
	}

	return ginx.Result{
		Data: ToUserVO(u),
	}, nil
}

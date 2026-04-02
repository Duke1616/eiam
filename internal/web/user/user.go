package user

import (
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	usersvc "github.com/Duke1616/eiam/internal/service/user"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc usersvc.IUserService
}

func NewUserHandler(svc usersvc.IUserService) *Handler {
	return &Handler{
		svc: svc,
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
	g := server.Group("/users")
	g.POST("/signup", ginx.BS[SignupRequest](h.Signup))
	
	// 显式拆分：通过 Path 区分认证源
	g.POST("/ldap/login", ginx.BS[LoginLdapRequest](h.LoginLdap))
	g.POST("/system/login", ginx.BS[LoginSystemRequest](h.LoginSystem))
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/users")
	g.GET("/profile", ginx.W(h.Profile))
}

// Signup 账号注册
func (h *Handler) Signup(ctx *ginx.Context, req SignupRequest, sess session.Session) (ginx.Result, error) {
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
func (h *Handler) LoginLdap(ctx *ginx.Context, req LoginLdapRequest, sess session.Session) (ginx.Result, error) {
	// 固定 provider 为 "ldap"
	u, err := h.svc.Login(ctx.Request.Context(), "ldap", req.Username, req.Password)
	if err != nil {
		return ErrUnauthorized, err
	}

	return h.onLoginSuccess(ctx, sess, u)
}

// LoginSystem 专用系统本地账密登录处理函数
func (h *Handler) LoginSystem(ctx *ginx.Context, req LoginSystemRequest, sess session.Session) (ginx.Result, error) {
	// 固定 provider 为 "local"
	u, err := h.svc.Login(ctx.Request.Context(), "local", req.Username, req.Password)
	if err != nil {
		return ErrUnauthorized, err
	}

	return h.onLoginSuccess(ctx, sess, u)
}

// onLoginSuccess 统一登录成功后的收口逻辑 (下发会话)
func (h *Handler) onLoginSuccess(ctx *ginx.Context, sess session.Session, u domain.User) (ginx.Result, error) {
	if err := sess.Set(ctx.Request.Context(), "uid", u.ID); err != nil {
		return ErrInternalServer, err
	}

	return ginx.Result{
		Msg:  fmt.Sprintf("登录成功，账号：%s", u.Username),
		Data: u.ID,
	}, nil
}

// Profile 获取资料
func (h *Handler) Profile(ctx *ginx.Context) (ginx.Result, error) {
	sess, err := session.Get(ctx)
	if err != nil {
		return ErrUnauthenticated, err
	}

	// 修正：Int64() 在这里返回 (int64, error)
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

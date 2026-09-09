package idp

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
	"github.com/spf13/viper"
)

// UserSession 统一封装主站已认证用户的上下文凭据
type UserSession struct {
	Session  session.Session
	Claims   session.Claims
	UserID   int64
	TenantID int64
	Username string
}

// IsAuthenticated 校验当前会话是否具备合法登录凭据
func (s *UserSession) IsAuthenticated() bool {
	return s != nil && s.UserID > 0
}

// getUserSession 安全解析当前请求的 Session 会话并提取用户上下文
func (h *Handler) getUserSession(c *gin.Context) *UserSession {
	sess, err := session.Get(&ginx.Context{Context: c})
	claims := session.Claims{}
	if err == nil && sess != nil {
		claims = sess.Claims()
	}

	var username string
	var tid int64
	if sess != nil {
		username, _ = sess.Get(c.Request.Context(), "username").AsString()
		tid, _ = sess.Get(c.Request.Context(), "tenant_id").AsInt64()
	}

	return &UserSession{
		Session:  sess,
		Claims:   claims,
		UserID:   claims.Uid,
		TenantID: tid,
		Username: username,
	}
}

// requireAuth 统一登录态拦截检查：
// 若用户未登录，自动发起 302 重定向跳转至配置的统一登录页并携带当前完整 URL；
// 若用户已登录，返回解析完毕的 UserSession 上下文。
func (h *Handler) requireAuth(c *gin.Context) (*UserSession, bool) {
	userSess := h.getUserSession(c)
	if !userSess.IsAuthenticated() {
		h.redirectToLogin(c)
		return nil, false
	}
	return userSess, true
}

// redirectToLogin 统一将未认证客户端重定向至登录页并携带原路径作为回跳参数
func (h *Handler) redirectToLogin(c *gin.Context) {
	loginURL := lo.CoalesceOrEmpty(viper.GetString("idp.login_url"), "/login")
	rawReqURL := c.Request.URL.RequestURI()
	c.Redirect(http.StatusFound, fmt.Sprintf("%s?redirect=%s", loginURL, url.QueryEscape(rawReqURL)))
}

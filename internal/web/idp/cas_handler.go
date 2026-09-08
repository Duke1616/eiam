package idp

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Duke1616/eiam/internal/errs"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
	"github.com/spf13/viper"
)

// CasLogin 处理 CAS 登录与授票端点 (GET /cas/login)
// 适配 JumpServer 等开源系统的 CAS SSO 登录跳转，全面支持 gateway 与 renew 参数
func (h *Handler) CasLogin(c *gin.Context) {
	service := c.Query("service")
	if service == "" {
		c.String(http.StatusBadRequest, "缺少必要参数: service")
		return
	}

	// 基础安全校验：service 必须为合法的绝对 URL，防止恶意畸形构造与协议注入
	parsedService, err := url.Parse(service)
	if err != nil || !parsedService.IsAbs() {
		c.String(http.StatusBadRequest, "非法的目标服务地址 (service 必须为完整绝对 URL)")
		return
	}

	renew := c.DefaultQuery("renew", "false") == "true"
	gateway := c.DefaultQuery("gateway", "false") == "true"

	userSess := h.getUserSession(c)

	// 2. 状态判断：未登录 或 renew 强制重新认证
	if !userSess.IsAuthenticated() || renew {
		// CAS gateway 规范：未登录时若指定了 gateway=true，不跳转登录页，直接带空参数回跳目标系统
		if gateway && !userSess.IsAuthenticated() {
			c.Redirect(http.StatusFound, service)
			return
		}

		h.redirectToLogin(c)
		return
	}

	// 3. 用户已登录，签发 Service Ticket (ST-xxxx)
	ticket, err := h.casSvc.GenerateTicket(c.Request.Context(), userSess.UserID, userSess.TenantID, userSess.Username, service)
	if err != nil {
		if errors.Is(err, errs.ErrCasServiceNotRegistered) {
			c.String(http.StatusForbidden, "目标服务未在当前租户或系统级接入应用白名单中注册，拒绝跳转")
			return
		}
		h.logger.Error("生成 CAS Service Ticket 失败", elog.FieldErr(err))
		c.String(http.StatusInternalServerError, "生成单点登录凭据失败")
		return
	}

	// 4. 重定向回目标业务系统，拼接 ticket 参数
	redirectTarget := appendTicketToURL(service, ticket)
	c.Redirect(http.StatusFound, redirectTarget)
}

// CasServiceValidate 处理 CAS 2.0 / 3.0 服务票据验证端点
// 路径匹配: GET /cas/serviceValidate 与 GET /cas/p3/serviceValidate
// 规范自适应支持: 默认 XML 输出，当传入 ?format=json 或 Accept 包含 application/json 时返回 CAS 3.0 JSON
func (h *Handler) CasServiceValidate(c *gin.Context) {
	service := c.Query("service")
	ticket := c.Query("ticket")

	isJSON := strings.EqualFold(c.Query("format"), "json") ||
		strings.Contains(strings.ToLower(c.GetHeader("Accept")), "application/json")

	if service == "" || ticket == "" {
		h.logger.Warn("CAS 验票参数缺失", elog.String("service", service), elog.String("ticket", ticket))
		if isJSON {
			c.JSON(http.StatusOK, h.casSvc.BuildFailureJSON("INVALID_REQUEST", "缺少 ticket 或 service 参数"))
			return
		}
		c.Header("Content-Type", "application/xml; charset=utf-8")
		c.String(http.StatusOK, h.casSvc.BuildFailureXML("INVALID_REQUEST", "缺少 ticket 或 service 参数"))
		return
	}

	result, err := h.casSvc.ValidateTicket(c.Request.Context(), ticket, service)
	if err != nil {
		h.logger.Warn("CAS 票据核销失败",
			elog.String("ticket", ticket),
			elog.String("service", service),
			elog.FieldErr(err),
		)
		if isJSON {
			c.JSON(http.StatusOK, h.casSvc.BuildFailureJSON("INVALID_TICKET", err.Error()))
			return
		}
		c.Header("Content-Type", "application/xml; charset=utf-8")
		c.String(http.StatusOK, h.casSvc.BuildFailureXML("INVALID_TICKET", err.Error()))
		return
	}

	h.logger.Info("CAS 票据核销成功并签发用户信息",
		elog.String("ticket", ticket),
		elog.String("service", service),
		elog.String("username", result.User.Username),
		elog.Int64("user_id", result.User.ID),
	)

	if isJSON {
		c.JSON(http.StatusOK, h.casSvc.BuildSuccessJSON(result))
		return
	}

	c.Header("Content-Type", "application/xml; charset=utf-8")
	c.String(http.StatusOK, h.casSvc.BuildSuccessXML(result))
}

// CasValidate 处理 CAS 1.0 文本协议验证端点 (GET /cas/validate)
// 返回 plain text: yes\nusername 或 no\n
func (h *Handler) CasValidate(c *gin.Context) {
	service := c.Query("service")
	ticket := c.Query("ticket")

	c.Header("Content-Type", "text/plain; charset=utf-8")

	if service == "" || ticket == "" {
		c.String(http.StatusOK, "no\n")
		return
	}

	ok, username := h.casSvc.ValidatePlainText(c.Request.Context(), ticket, service)
	if !ok {
		c.String(http.StatusOK, "no\n")
		return
	}

	c.String(http.StatusOK, fmt.Sprintf("yes\n%s\n", username))
}

// CasLogout 处理 CAS 单点登出端点 (GET /cas/logout)
func (h *Handler) CasLogout(c *gin.Context) {
	service := c.Query("service")
	if service == "" {
		service = c.Query("url")
	}

	// 销毁当前 Session
	sess, err := session.Get(&ginx.Context{Context: c})
	if err == nil && sess != nil {
		_ = sess.Destroy(&ginx.Context{Context: c})
	}

	if service != "" {
		c.Redirect(http.StatusFound, service)
		return
	}

	loginURL := viper.GetString("idp.login_url")
	if loginURL == "" {
		loginURL = "/login"
	}
	c.Redirect(http.StatusFound, loginURL)
}

// appendTicketToURL 使用标准库 url.Parse 解析目标地址并安全注入 ticket query 参数，
// 完美适配已存在查询参数或 URL Fragment（锚点）的场景，防止 ticket 参数被错误拼接到 Fragment 之后
func appendTicketToURL(targetURL, ticket string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		return fmt.Sprintf("%s%sticket=%s", targetURL, sep, url.QueryEscape(ticket))
	}

	q := u.Query()
	q.Set("ticket", ticket)
	u.RawQuery = q.Encode()
	return u.String()
}

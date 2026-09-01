package discovery

import (
	"net/http"
	"strings"

	"github.com/Duke1616/eiam/internal/service/discovery"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
	"github.com/samber/lo"
	"github.com/spf13/viper"
)

const ctxAuthorizedServiceKey = "_discovery_authorized_service"

type Handler struct {
	svc      discovery.IDiscoveryService
	tokenSvc discovery.ITokenService
	logger   *elog.Component
}

func NewHandler(svc discovery.IDiscoveryService, tokenSvc discovery.ITokenService) *Handler {
	return &Handler{
		svc:      svc,
		tokenSvc: tokenSvc,
		logger:   elog.DefaultLogger.With(elog.FieldComponent("discovery-handler")),
	}
}

// AuthMiddleware 微服务资产上报鉴权中间件：
// 1. 若 discovery.auth_enabled 为 false (默认)，零配置直接放行；
// 2. 若开启认证，严格校验统一专属令牌 (eiam_sct_...)。
func (h *Handler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !viper.GetBool("discovery.auth_enabled") {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader || strings.TrimSpace(token) == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrInvalidToken)
			return
		}

		serviceName, err := h.tokenSvc.VerifyToken(c.Request.Context(), strings.TrimSpace(token))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrInvalidToken)
			return
		}

		c.Set(ctxAuthorizedServiceKey, serviceName)
		c.Next()
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
	g := server.Group("/api/v1/discovery")
	g.Use(h.AuthMiddleware())

	// 接收资产同步请求 (支持 HTTP 代理模式)
	g.POST("/sync", ginx.B[capability.SyncRequest](h.Sync))
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
}

// Sync 接收微服务资产上报并转交给 IDiscoveryService 处理
func (h *Handler) Sync(ctx *ginx.Context, req capability.SyncRequest) (ginx.Result, error) {
	if req.Service == "" {
		return ErrInvalidService, nil
	}

	// 强服务归属防越权校验：若当前请求是由专属 Token 认证通过的，必须匹配其绑定的微服务标识
	if authorizedService, exists := ctx.Get(ctxAuthorizedServiceKey); exists {
		if expectedService, ok := authorizedService.(string); ok && expectedService != "" {
			if expectedService != req.Service {
				return ErrServiceMismatch, nil
			}
		}
	}

	currentHash := req.Hash()

	// 委托给 Service 层执行分布式比对与并发互斥对账
	isNew, err := h.svc.Sync(ctx.Request.Context(), req)
	if err != nil {
		return ErrSyncFailed, err
	}

	// 声明式三元判断提示文案
	msg := lo.Ternary(isNew, "资产同步指令已接收", "资产未变更，已就绪")

	return ginx.Result{
		Msg: msg,
		Data: gin.H{
			"hash":   currentHash,
			"synced": true,
		},
	}, nil
}




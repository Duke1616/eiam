package resource

import (
	resourceinit "github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	initSvc resourceinit.IInitializer
}

func NewHandler(initSvc resourceinit.IInitializer) *Handler {
	return &Handler{
		initSvc: initSvc,
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
	g := server.Group("/api/resource")
	// 资产发现同步入口 (SDK 模式)
	g.POST("/discovery/sync", ginx.B[capability.SyncRequest](h.SyncDiscovery))
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {
}

// SyncDiscovery 接收并处理来自微服务 SDK 的全量资产上报
func (h *Handler) SyncDiscovery(ctx *ginx.Context, req capability.SyncRequest) (ginx.Result, error) {
	// 直接交付给标准化初始引擎处理回调
	if err := h.initSvc.SyncSDKDiscovery(ctx.Request.Context(), req); err != nil {
		return ErrSyncFailed, err
	}

	return ginx.Result{
		Msg: "资产上报同步成功",
	}, nil
}

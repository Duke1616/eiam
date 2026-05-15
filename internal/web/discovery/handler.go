package discovery

import (
	"context"

	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	registry capability.Registry
}

func NewHandler(registry capability.Registry) *Handler {
	return &Handler{
		registry: registry,
	}
}

func (h *Handler) PublicRoutes(server *gin.Engine) {
	g := server.Group("/api/v1/discovery")

	// 使用 ginx 包装处理函数
	g.POST("/sync", ginx.B[capability.SyncRequest](h.Sync))
}

func (h *Handler) PrivateRoutes(server *gin.Engine) {

}

// Sync 接收微服务资产上报并转交给 Registry 处理 (支持 HTTP 代理模式)
func (h *Handler) Sync(ctx *ginx.Context, req capability.SyncRequest) (ginx.Result, error) {
	if req.Service == "" {
		return ErrInvalidService, nil
	}

	// 直接复用 Registry 的逻辑
	// 注意：这里使用 context.Background() 因为 Sync 是后台长任务，不应随请求结束而取消
	if err := h.registry.Sync(context.Background(), req); err != nil {
		return ErrSyncFailed, err
	}

	return ginx.Result{
		Msg: "资产同步指令已接收",
		Data: gin.H{
			"hash": req.Hash(),
		},
	}, nil
}

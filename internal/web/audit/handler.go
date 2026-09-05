package audit

import (
	"github.com/Duke1616/eiam/internal/domain"
	auditevt "github.com/Duke1616/eiam/internal/event/audit"
	auditsvc "github.com/Duke1616/eiam/internal/service/audit"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

// Handler 审计 HTTP 控制器
type Handler struct {
	capability.IRegistry
	svc      auditsvc.IAuditService
	producer auditevt.IAuditProducer
}

// NewHandler 构建审计 Web 控制器实例
func NewHandler(svc auditsvc.IAuditService, producer auditevt.IAuditProducer) *Handler {
	return &Handler{
		IRegistry: capability.NewRegistry("iam", "audit", "安全审计"),
		svc:       svc,
		producer:  producer,
	}
}

// PublicRoutes 注册开放给微服务 SDK 的批量上报端点
func (h *Handler) PublicRoutes(server *gin.Engine) {
	server.POST("/api/audit/batch", ginx.B[BatchOperationReq](h.ReportBatchOperations))
}

// ReportBatchOperations 接收微服务 SDK 批量聚合上报的操作审计日志 (零阻塞入队)
func (h *Handler) ReportBatchOperations(ctx *ginx.Context, req BatchOperationReq) (ginx.Result, error) {
	reqCtx := ctx.Request.Context()
	lo.ForEach(req.Records, func(r OperationLogRecord, _ int) {
		_ = h.producer.RecordOperation(reqCtx, domain.OperationLog{
			TenantID:     r.TenantID,
			Service:      r.Service,
			OperatorID:   r.OperatorID,
			OperatorName: r.OperatorName,
			Module:       r.Module,
			Action:       r.Action,
			ResourceID:   r.ResourceID,
			ResourceName: r.ResourceName,
			ResourceURN:  r.ResourceURN,
			AfterState:   r.AfterState,
			Status:       r.Status,
			FailReason:   r.FailReason,
			ClientIP:     r.ClientIP,
			UserAgent:    r.UserAgent,
			Ctime:        r.Ctime,
		})
	})
	return ginx.Result{Msg: "ok"}, nil
}

// PrivateRoutes 注册审计管理私有路由
func (h *Handler) PrivateRoutes(server *gin.Engine) {
	g := server.Group("/api/audit")

	g.POST("/auth/list", h.Define("查看认证审计", "view_auth").
		Bind(ginx.B[ListAuthLogReq](h.ListAuthLogs)),
	)
	g.POST("/operation/list", h.Define("查看操作审计", "view_operation").
		Bind(ginx.B[ListOperationLogReq](h.ListOperationLogs)),
	)
}

// ListAuthLogs 分页查询认证审计日志
func (h *Handler) ListAuthLogs(ctx *ginx.Context, req ListAuthLogReq) (ginx.Result, error) {
	reqCtx := ctx.Request.Context()

	filter := domain.AuthLogFilter{
		Username:  req.Username,
		AuthType:  req.AuthType,
		Status:    req.Status,
		StartTime: req.StartTime,
		EndTime:   req.EndTime,
	}

	logs, total, err := h.svc.ListAuthLogs(reqCtx, filter, int(req.Offset), int(req.Limit))
	if err != nil {
		return ErrListAuthLogsFailed, err
	}

	items := lo.Map(logs, func(item domain.AuthLog, _ int) AuthLogVO {
		return toAuthLogVO(item)
	})

	return ginx.Result{
		Data: ListAuthLogResp{
			Total: total,
			List:  items,
		},
	}, nil
}

// ListOperationLogs 分页查询业务管理操作审计日志
func (h *Handler) ListOperationLogs(ctx *ginx.Context, req ListOperationLogReq) (ginx.Result, error) {
	reqCtx := ctx.Request.Context()

	filter := domain.OperationLogFilter{
		Service:      req.Service,
		Module:       req.Module,
		Action:       req.Action,
		Status:       req.Status,
		OperatorName: req.OperatorName,
		StartTime:    req.StartTime,
		EndTime:      req.EndTime,
	}

	logs, total, err := h.svc.ListOperationLogs(reqCtx, filter, int(req.Offset), int(req.Limit))
	if err != nil {
		return ErrListOperationLogsFailed, err
	}

	items := lo.Map(logs, func(item domain.OperationLog, _ int) OperationLogVO {
		return toOperationLogVO(item)
	})

	return ginx.Result{
		Data: ListOperationLogResp{
			Total: total,
			List:  items,
		},
	}, nil
}

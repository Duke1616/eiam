package sdk

import (
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/gin-gonic/gin"
)

// OperationRecord 微服务上报的操作审计数据载荷
type OperationRecord struct {
	TenantID     int64  `json:"tenant_id"`
	Service      string `json:"service"` // 业务微服务标识，如: ecmdb, etask
	OperatorID   int64  `json:"operator_id"`
	OperatorName string `json:"operator_name,omitempty"`
	Module       string `json:"module"`
	Action       string `json:"action"`
	ResourceID   string `json:"resource_id,omitempty"`
	ResourceName string `json:"resource_name,omitempty"`
	ResourceURN  string `json:"resource_urn"`
	AfterState   string `json:"after_state,omitempty"`
	Status       string `json:"status"`
	FailReason   string `json:"fail_reason,omitempty"`
	ClientIP     string `json:"client_ip"`
	UserAgent    string `json:"user_agent"`
	Ctime        int64  `json:"ctime"`
}

// extractParam 探测路由参数中的资源唯一标识
func extractParam(ctx *gin.Context) string {
	return capability.ExtractResourceParam(ctx)
}

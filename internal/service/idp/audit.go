package idp

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	auditevt "github.com/Duke1616/eiam/internal/event/audit"
	"github.com/Duke1616/eiam/pkg/ctxutil"
)

// recordAudit 异步记录 IDP 域操作审计日志
func recordAudit(ctx context.Context, p auditevt.IAuditProducer, tenantID int64, action, resourceID, resourceName, status, failReason string) {
	if p == nil {
		return
	}

	// 提前在主上下文提取客户端信息，避免异步协程产生上下文生命周期竞争
	clientIP := ctxutil.GetClientIP(ctx)
	userAgent := ctxutil.GetUserAgent(ctx)

	go func() {
		defer func() { _ = recover() }()
		asyncCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		_ = p.RecordOperation(asyncCtx, domain.OperationLog{
			TenantID:     tenantID,
			Service:      "iam",
			Module:       "idp",
			Action:       action,
			ResourceID:   resourceID,
			ResourceName: resourceName,
			Status:       status,
			FailReason:   failReason,
			ClientIP:     clientIP,
			UserAgent:    userAgent,
			Ctime:        time.Now().UnixMilli(),
		})
	}()
}

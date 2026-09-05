package audit

import "github.com/Duke1616/eiam/internal/domain"

// ListAuthLogReq 认证审计日志查询入参
type ListAuthLogReq struct {
	Offset    int64  `json:"offset"`
	Limit     int64  `json:"limit"`
	Username  string `json:"username"`
	AuthType  string `json:"auth_type"`
	Status    string `json:"status"`
	StartTime int64  `json:"start_time"`
	EndTime   int64  `json:"end_time"`
}

// AuthLogVO 认证审计日志前端展示对象
type AuthLogVO struct {
	ID         int64  `json:"id"`
	TenantID   int64  `json:"tenant_id"`
	UserID     int64  `json:"user_id"`
	Username   string `json:"username"`
	AuthType   string `json:"auth_type"`
	Status     string `json:"status"`
	FailReason string `json:"fail_reason"`
	ClientIP   string `json:"client_ip"`
	UserAgent  string `json:"user_agent"`
	Ctime      int64  `json:"ctime"`
}

// ListAuthLogResp 认证审计日志查询结果
type ListAuthLogResp struct {
	Total int64       `json:"total"`
	List  []AuthLogVO `json:"list"`
}

// ListOperationLogReq 操作审计日志查询入参 (严格对齐前端检索面板)
type ListOperationLogReq struct {
	Offset       int64  `json:"offset"`
	Limit        int64  `json:"limit"`
	Service      string `json:"service"`
	Module       string `json:"module"`
	Action       string `json:"action"`
	Status       string `json:"status"`
	OperatorName string `json:"operator_name"`
	StartTime    int64  `json:"start_time"`
	EndTime      int64  `json:"end_time"`
}

// OperationLogVO 操作审计日志前端展示对象
type OperationLogVO struct {
	ID           int64  `json:"id"`
	TenantID     int64  `json:"tenant_id"`
	Service      string `json:"service"`
	OperatorID   int64  `json:"operator_id"`
	OperatorName string `json:"operator_name"`
	Module       string `json:"module"`
	Action       string `json:"action"`
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
	ResourceURN  string `json:"resource_urn"`
	BeforeState  string `json:"before_state"`
	AfterState   string `json:"after_state"`
	Status       string `json:"status"`
	FailReason   string `json:"fail_reason"`
	ClientIP     string `json:"client_ip"`
	UserAgent    string `json:"user_agent"`
	Ctime        int64  `json:"ctime"`
}

// ListOperationLogResp 操作审计日志查询结果
type ListOperationLogResp struct {
	Total int64            `json:"total"`
	List  []OperationLogVO `json:"list"`
}

func toAuthLogVO(l domain.AuthLog) AuthLogVO {
	return AuthLogVO{
		ID:         l.ID,
		TenantID:   l.TenantID,
		UserID:     l.UserID,
		Username:   l.Username,
		AuthType:   l.AuthType,
		Status:     l.Status,
		FailReason: l.FailReason,
		ClientIP:   l.ClientIP,
		UserAgent:  l.UserAgent,
		Ctime:      l.Ctime,
	}
}

func toOperationLogVO(l domain.OperationLog) OperationLogVO {
	return OperationLogVO{
		ID:           l.ID,
		TenantID:     l.TenantID,
		Service:      l.Service,
		OperatorID:   l.OperatorID,
		OperatorName: l.OperatorName,
		Module:       l.Module,
		Action:       l.Action,
		ResourceID:   l.ResourceID,
		ResourceName: l.ResourceName,
		ResourceURN:  l.ResourceURN,
		BeforeState:  l.BeforeState,
		AfterState:   l.AfterState,
		Status:       l.Status,
		FailReason:   l.FailReason,
		ClientIP:     l.ClientIP,
		UserAgent:    l.UserAgent,
		Ctime:        l.Ctime,
	}
}

// BatchOperationReq 微服务 SDK 批量上报操作审计载荷
type BatchOperationReq struct {
	Records []OperationLogRecord `json:"records"`
}

// OperationLogRecord 单条操作审计明细
type OperationLogRecord struct {
	TenantID     int64  `json:"tenant_id"`
	Service      string `json:"service"`
	OperatorID   int64  `json:"operator_id"`
	OperatorName string `json:"operator_name"`
	Module       string `json:"module"`
	Action       string `json:"action"`
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
	ResourceURN  string `json:"resource_urn"`
	AfterState   string `json:"after_state"`
	Status       string `json:"status"`
	FailReason   string `json:"fail_reason"`
	ClientIP     string `json:"client_ip"`
	UserAgent    string `json:"user_agent"`
	Ctime        int64  `json:"ctime"`
}

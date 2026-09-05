package repository

import (
	"context"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/dao"
	"github.com/samber/lo"
)

// IAuditRepository 安全审计仓储接口 (专注于认证与操作审计领域对象的持久化与多维检索)
//
//go:generate mockgen -package=repomocks -destination=./mocks/audit.mock.go github.com/Duke1616/eiam/internal/repository IAuditRepository
type IAuditRepository interface {
	// BatchSaveAuthLogs 批量持久化认证审计领域实体
	BatchSaveAuthLogs(ctx context.Context, logs []domain.AuthLog) error
	// BatchSaveOperationLogs 批量持久化业务操作审计领域实体
	BatchSaveOperationLogs(ctx context.Context, logs []domain.OperationLog) error
	// ListAuthLogs 分页检索认证审计记录并转化为领域对象
	ListAuthLogs(ctx context.Context, filter domain.AuthLogFilter, offset, limit int) ([]domain.AuthLog, int64, error)
	// ListOperationLogs 分页检索业务管理操作审计记录并转化为领域对象
	ListOperationLogs(ctx context.Context, filter domain.OperationLogFilter, offset, limit int) ([]domain.OperationLog, int64, error)
}

type auditRepository struct {
	dao dao.IAuditDAO
}

// NewAuditRepository 构建纯粹的安全审计数据仓储实例
func NewAuditRepository(dao dao.IAuditDAO) IAuditRepository {
	return &auditRepository{
		dao: dao,
	}
}

func (r *auditRepository) BatchSaveAuthLogs(ctx context.Context, logs []domain.AuthLog) error {
	if len(logs) == 0 {
		return nil
	}
	daoLogs := lo.Map(logs, func(l domain.AuthLog, _ int) dao.AuditAuthLog {
		return r.toAuthDAO(l)
	})
	return r.dao.BatchInsertAuthLogs(ctx, daoLogs)
}

func (r *auditRepository) BatchSaveOperationLogs(ctx context.Context, logs []domain.OperationLog) error {
	if len(logs) == 0 {
		return nil
	}
	daoLogs := lo.Map(logs, func(l domain.OperationLog, _ int) dao.AuditOperationLog {
		return r.toOpDAO(l)
	})
	return r.dao.BatchInsertOperationLogs(ctx, daoLogs)
}

func (r *auditRepository) ListAuthLogs(ctx context.Context, filter domain.AuthLogFilter, offset, limit int) ([]domain.AuthLog, int64, error) {
	daoLogs, total, err := r.dao.ListAuthLogs(ctx, filter, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	logs := lo.Map(daoLogs, func(l dao.AuditAuthLog, _ int) domain.AuthLog {
		return r.toAuthDomain(l)
	})
	return logs, total, nil
}

func (r *auditRepository) ListOperationLogs(ctx context.Context, filter domain.OperationLogFilter, offset, limit int) ([]domain.OperationLog, int64, error) {
	daoLogs, total, err := r.dao.ListOperationLogs(ctx, filter, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	logs := lo.Map(daoLogs, func(l dao.AuditOperationLog, _ int) domain.OperationLog {
		return r.toOpDomain(l)
	})
	return logs, total, nil
}

func (r *auditRepository) toAuthDAO(l domain.AuthLog) dao.AuditAuthLog {
	ctime := l.Ctime
	if ctime <= 0 {
		ctime = time.Now().UnixMilli()
	}
	return dao.AuditAuthLog{
		Id:         l.ID,
		TenantId:   l.TenantID,
		UserId:     l.UserID,
		Username:   l.Username,
		AuthType:   l.AuthType,
		Status:     l.Status,
		FailReason: l.FailReason,
		ClientIp:   l.ClientIP,
		UserAgent:  l.UserAgent,
		Ctime:      ctime,
	}
}

func (r *auditRepository) toAuthDomain(l dao.AuditAuthLog) domain.AuthLog {
	return domain.AuthLog{
		ID:         l.Id,
		TenantID:   l.TenantId,
		UserID:     l.UserId,
		Username:   l.Username,
		AuthType:   l.AuthType,
		Status:     l.Status,
		FailReason: l.FailReason,
		ClientIP:   l.ClientIp,
		UserAgent:  l.UserAgent,
		Ctime:      l.Ctime,
	}
}

func (r *auditRepository) toOpDAO(l domain.OperationLog) dao.AuditOperationLog {
	ctime := l.Ctime
	if ctime <= 0 {
		ctime = time.Now().UnixMilli()
	}
	return dao.AuditOperationLog{
		Id:           l.ID,
		TenantId:     l.TenantID,
		Service:      l.Service,
		OperatorId:   l.OperatorID,
		OperatorName: l.OperatorName,
		Module:       l.Module,
		Action:       l.Action,
		ResourceId:   l.ResourceID,
		ResourceName: l.ResourceName,
		ResourceUrn:  l.ResourceURN,
		BeforeState:  l.BeforeState,
		AfterState:   l.AfterState,
		Status:       l.Status,
		FailReason:   l.FailReason,
		ClientIp:     l.ClientIP,
		UserAgent:    l.UserAgent,
		Ctime:        ctime,
	}
}

func (r *auditRepository) toOpDomain(l dao.AuditOperationLog) domain.OperationLog {
	return domain.OperationLog{
		ID:           l.Id,
		TenantID:     l.TenantId,
		Service:      l.Service,
		OperatorID:   l.OperatorId,
		OperatorName: l.OperatorName,
		Module:       l.Module,
		Action:       l.Action,
		ResourceID:   l.ResourceId,
		ResourceName: l.ResourceName,
		ResourceURN:  l.ResourceUrn,
		BeforeState:  l.BeforeState,
		AfterState:   l.AfterState,
		Status:       l.Status,
		FailReason:   l.FailReason,
		ClientIP:     l.ClientIp,
		UserAgent:    l.UserAgent,
		Ctime:        l.Ctime,
	}
}

package audit

import (
	"context"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
)

// IAuditService 审计业务服务接口
type IAuditService interface {
	// ListAuthLogs 分页查询认证安全审计日志
	ListAuthLogs(ctx context.Context, filter domain.AuthLogFilter, offset, limit int) ([]domain.AuthLog, int64, error)
	// ListOperationLogs 分页查询业务管理操作审计日志
	ListOperationLogs(ctx context.Context, filter domain.OperationLogFilter, offset, limit int) ([]domain.OperationLog, int64, error)
}

type auditService struct {
	repo repository.IAuditRepository
}

// NewService 构建审计服务实例
func NewService(repo repository.IAuditRepository) IAuditService {
	return &auditService{
		repo: repo,
	}
}

// ListAuthLogs 分页查询认证日志
func (s *auditService) ListAuthLogs(ctx context.Context, filter domain.AuthLogFilter, offset, limit int) ([]domain.AuthLog, int64, error) {
	return s.repo.ListAuthLogs(ctx, filter, offset, limit)
}

// ListOperationLogs 分页查询操作日志
func (s *auditService) ListOperationLogs(ctx context.Context, filter domain.OperationLogFilter, offset, limit int) ([]domain.OperationLog, int64, error) {
	return s.repo.ListOperationLogs(ctx, filter, offset, limit)
}

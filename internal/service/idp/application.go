package idp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	auditevt "github.com/Duke1616/eiam/internal/event/audit"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/google/uuid"
)

// IApplicationService 下游接入应用 (OIDC/CAS/SAML 等统一应用中心) 的生命周期管理接口
type IApplicationService interface {
	// CreateApplication 创建新的接入应用并生成初次客户端密钥
	CreateApplication(ctx context.Context, app domain.Application) (domain.Application, error)
	// UpdateApplication 更新接入应用基础信息与回调白名单
	UpdateApplication(ctx context.Context, app domain.Application) error
	// ResetApplicationSecret 重置接入应用的客户端密钥并返回新明文
	ResetApplicationSecret(ctx context.Context, id int64) (string, error)
	// GetApplicationByID 根据主键 ID 查询应用详情
	GetApplicationByID(ctx context.Context, id int64) (domain.Application, error)
	// GetApplicationByClientID 根据客户端标识查询应用配置
	GetApplicationByClientID(ctx context.Context, clientID string) (domain.Application, error)
	// ListApplications 分页查询指定租户下的接入应用列表
	ListApplications(ctx context.Context, tenantID int64, offset, limit int) ([]domain.Application, int64, error)
	// DeleteApplication 删除接入应用
	DeleteApplication(ctx context.Context, id int64) error
}

type applicationService struct {
	repo          repository.IApplicationRepository
	auditProducer auditevt.IAuditProducer
}

// NewApplicationService 构造接入应用管理服务实例
func NewApplicationService(
	repo repository.IApplicationRepository,
	auditProducer auditevt.IAuditProducer,
) IApplicationService {
	return &applicationService{
		repo:          repo,
		auditProducer: auditProducer,
	}
}

func (s *applicationService) CreateApplication(ctx context.Context, app domain.Application) (domain.Application, error) {
	app.InitDefaultConfig()
	if err := app.Validate(); err != nil {
		return domain.Application{}, err
	}

	if app.ClientID == "" {
		app.ClientID = fmt.Sprintf("app_%s", uuid.New().String()[:12])
	}

	rawSecret, err := s.generateSecret()
	if err != nil {
		return domain.Application{}, fmt.Errorf("生成客户端密钥失败: %w", err)
	}

	if err := app.SetSecret(rawSecret); err != nil {
		return domain.Application{}, fmt.Errorf("计算客户端密钥哈希失败: %w", err)
	}

	id, err := s.repo.Create(ctx, app)
	if err != nil {
		return domain.Application{}, err
	}

	app.ID = id
	app.ClientSecret = rawSecret

	s.recordAudit(ctx, app.TenantID, "create_application", app.ClientID, app.Name, domain.OpStatusSuccess, "")
	return app, nil
}

func (s *applicationService) UpdateApplication(ctx context.Context, app domain.Application) error {
	app.InitDefaultConfig()
	if err := app.Validate(); err != nil {
		return err
	}

	existing, err := s.repo.FindByID(ctx, app.ID)
	if err != nil {
		return errs.ErrApplicationNotFound
	}

	if err := s.repo.Update(ctx, app); err != nil {
		s.recordAudit(ctx, app.TenantID, "update_application", existing.ClientID, app.Name, domain.OpStatusFailed, err.Error())
		return err
	}

	s.recordAudit(ctx, app.TenantID, "update_application", existing.ClientID, app.Name, domain.OpStatusSuccess, "")
	return nil
}

func (s *applicationService) ResetApplicationSecret(ctx context.Context, id int64) (string, error) {
	existing, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return "", errs.ErrApplicationNotFound
	}

	newRawSecret, err := s.generateSecret()
	if err != nil {
		return "", fmt.Errorf("生成新密钥失败: %w", err)
	}

	var tempApp domain.Application
	if err := tempApp.SetSecret(newRawSecret); err != nil {
		return "", fmt.Errorf("计算新密钥哈希失败: %w", err)
	}

	if err := s.repo.UpdateSecret(ctx, id, tempApp.ClientSecretHash); err != nil {
		s.recordAudit(ctx, existing.TenantID, "reset_secret", existing.ClientID, existing.Name, domain.OpStatusFailed, err.Error())
		return "", err
	}

	s.recordAudit(ctx, existing.TenantID, "reset_secret", existing.ClientID, existing.Name, domain.OpStatusSuccess, "")
	return newRawSecret, nil
}

func (s *applicationService) GetApplicationByID(ctx context.Context, id int64) (domain.Application, error) {
	app, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return domain.Application{}, errs.ErrApplicationNotFound
	}
	return app, nil
}

func (s *applicationService) GetApplicationByClientID(ctx context.Context, clientID string) (domain.Application, error) {
	app, err := s.repo.FindByClientID(ctx, clientID)
	if err != nil {
		return domain.Application{}, errs.ErrApplicationNotFound
	}
	return app, nil
}

func (s *applicationService) ListApplications(ctx context.Context, tenantID int64, offset, limit int) ([]domain.Application, int64, error) {
	return s.repo.ListByTenantID(ctx, tenantID, offset, limit)
}

func (s *applicationService) DeleteApplication(ctx context.Context, id int64) error {
	app, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return errs.ErrApplicationNotFound
	}

	if err = s.repo.Delete(ctx, id); err != nil {
		s.recordAudit(ctx, app.TenantID, "delete_application", app.ClientID, app.Name, domain.OpStatusFailed, err.Error())
		return err
	}

	s.recordAudit(ctx, app.TenantID, "delete_application", app.ClientID, app.Name, domain.OpStatusSuccess, "")
	return nil
}

func (s *applicationService) generateSecret() (string, error) {
	return generateRandomString(32)
}

// recordAudit 异步记录审计操作日志
func (s *applicationService) recordAudit(ctx context.Context, tenantID int64, action, resourceID, resourceName, status, failReason string) {
	if s.auditProducer == nil {
		return
	}
	go func() {
		defer func() { _ = recover() }()
		asyncCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		_ = s.auditProducer.RecordOperation(asyncCtx, domain.OperationLog{
			TenantID:     tenantID,
			Service:      "iam",
			Module:       "idp",
			Action:       action,
			ResourceID:   resourceID,
			ResourceName: resourceName,
			Status:       status,
			FailReason:   failReason,
			ClientIP:     ctxutil.GetClientIP(ctx),
			UserAgent:    ctxutil.GetUserAgent(ctx),
			Ctime:        time.Now().UnixMilli(),
		})
	}()
}

// generateRandomString 生成指定长度的高强度加密随机字符串 (URL 安全)
func generateRandomString(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

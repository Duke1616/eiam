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

// IOAuthClientService 下游接入应用 (OAuth2/OIDC Relying Party) 的生命周期管理接口
type IOAuthClientService interface {
	// CreateClient 创建新的接入应用并生成初次客户端密钥
	CreateClient(ctx context.Context, client domain.OAuthClient) (domain.OAuthClient, error)
	// UpdateClient 更新接入应用基础信息与回调白名单
	UpdateClient(ctx context.Context, client domain.OAuthClient) error
	// ResetClientSecret 重置接入应用的客户端密钥并返回新明文
	ResetClientSecret(ctx context.Context, id int64) (string, error)
	// GetClientByID 根据主键 ID 查询应用详情
	GetClientByID(ctx context.Context, id int64) (domain.OAuthClient, error)
	// GetClientByClientID 根据客户端标识查询应用配置
	GetClientByClientID(ctx context.Context, clientID string) (domain.OAuthClient, error)
	// ListClients 分页查询指定租户下的接入应用列表
	ListClients(ctx context.Context, tenantID int64, offset, limit int) ([]domain.OAuthClient, int64, error)
	// DeleteClient 删除接入应用
	DeleteClient(ctx context.Context, id int64) error
}

type oauthClientService struct {
	repo          repository.IOAuthClientRepository
	auditProducer auditevt.IAuditProducer
}

// NewOAuthClientService 构造接入应用管理服务实例
func NewOAuthClientService(
	repo repository.IOAuthClientRepository,
	auditProducer auditevt.IAuditProducer,
) IOAuthClientService {
	return &oauthClientService{
		repo:          repo,
		auditProducer: auditProducer,
	}
}

// CreateClient 创建应用并自动生成安全密钥
func (s *oauthClientService) CreateClient(ctx context.Context, client domain.OAuthClient) (domain.OAuthClient, error) {
	if !client.ValidateRedirectURIs() {
		return domain.OAuthClient{}, errs.ErrInvalidRedirectURI
	}

	if client.ClientID == "" {
		client.ClientID = fmt.Sprintf("app_%s", uuid.New().String()[:12])
	}

	rawSecret, err := generateRandomString(32)
	if err != nil {
		return domain.OAuthClient{}, fmt.Errorf("生成客户端密钥失败: %w", err)
	}

	if err = client.SetSecret(rawSecret); err != nil {
		return domain.OAuthClient{}, fmt.Errorf("计算客户端密钥哈希失败: %w", err)
	}

	client.InitDefaultConfig()

	id, err := s.repo.Create(ctx, client)
	if err != nil {
		s.recordAudit(ctx, client.TenantID, "create_client", client.ClientID, client.Name, domain.OpStatusFailed, err.Error())
		return domain.OAuthClient{}, err
	}
	client.ID = id

	s.recordAudit(ctx, client.TenantID, "create_client", client.ClientID, client.Name, domain.OpStatusSuccess, "")
	return client, nil
}

// UpdateClient 修改应用配置
func (s *oauthClientService) UpdateClient(ctx context.Context, client domain.OAuthClient) error {
	if !client.ValidateRedirectURIs() {
		return errs.ErrInvalidRedirectURI
	}

	existing, err := s.repo.FindByID(ctx, client.ID)
	if err != nil {
		return errs.ErrOAuthClientNotFound
	}

	if err = s.repo.Update(ctx, client); err != nil {
		s.recordAudit(ctx, existing.TenantID, "update_client", existing.ClientID, client.Name, domain.OpStatusFailed, err.Error())
		return err
	}

	s.recordAudit(ctx, existing.TenantID, "update_client", existing.ClientID, client.Name, domain.OpStatusSuccess, "")
	return nil
}

// ResetClientSecret 重置密钥
func (s *oauthClientService) ResetClientSecret(ctx context.Context, id int64) (string, error) {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return "", errs.ErrOAuthClientNotFound
	}

	rawSecret, err := generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("生成客户端密钥失败: %w", err)
	}

	if err = client.SetSecret(rawSecret); err != nil {
		return "", fmt.Errorf("计算客户端密钥哈希失败: %w", err)
	}

	if err = s.repo.UpdateSecret(ctx, id, client.ClientSecretHash); err != nil {
		s.recordAudit(ctx, client.TenantID, "reset_secret", client.ClientID, client.Name, domain.OpStatusFailed, err.Error())
		return "", err
	}

	s.recordAudit(ctx, client.TenantID, "reset_secret", client.ClientID, client.Name, domain.OpStatusSuccess, "")
	return rawSecret, nil
}

// GetClientByID 根据 ID 获取应用详情
func (s *oauthClientService) GetClientByID(ctx context.Context, id int64) (domain.OAuthClient, error) {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return domain.OAuthClient{}, errs.ErrOAuthClientNotFound
	}
	return client, nil
}

// GetClientByClientID 根据 ClientID 获取应用详情
func (s *oauthClientService) GetClientByClientID(ctx context.Context, clientID string) (domain.OAuthClient, error) {
	client, err := s.repo.FindByClientID(ctx, clientID)
	if err != nil {
		return domain.OAuthClient{}, errs.ErrOAuthClientNotFound
	}
	return client, nil
}

// ListClients 分页查询指定租户下的应用列表
func (s *oauthClientService) ListClients(ctx context.Context, tenantID int64, offset, limit int) ([]domain.OAuthClient, int64, error) {
	return s.repo.ListByTenantID(ctx, tenantID, offset, limit)
}

// DeleteClient 删除应用
func (s *oauthClientService) DeleteClient(ctx context.Context, id int64) error {
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return errs.ErrOAuthClientNotFound
	}

	if err = s.repo.Delete(ctx, id); err != nil {
		s.recordAudit(ctx, client.TenantID, "delete_client", client.ClientID, client.Name, domain.OpStatusFailed, err.Error())
		return err
	}

	s.recordAudit(ctx, client.TenantID, "delete_client", client.ClientID, client.Name, domain.OpStatusSuccess, "")
	return nil
}

// recordAudit 异步记录审计操作日志
func (s *oauthClientService) recordAudit(ctx context.Context, tenantID int64, action, resourceID, resourceName, status, failReason string) {
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

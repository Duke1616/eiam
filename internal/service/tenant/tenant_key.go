package tenant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/pkg/gormx"
)

// ITenantKeyService 租户密钥管理服务：提供租户凭证的生命周期管理与有效性校验
type ITenantKeyService interface {
	// GenerateKey 为指定租户随机生成一对鉴权凭证（AccessKey/SecretKey）
	GenerateKey(ctx context.Context, tenantID int64, description string) (domain.TenantKey, error)
	// GetTenantIDByAccessKey 根据 AccessKey 快速查询租户 ID，用于租户有效性前置判定
	GetTenantIDByAccessKey(ctx context.Context, ak string) (int64, error)
	// VerifyKey 双重校验 AccessKey 与 SecretKey，用于第三方 API 调用的安全鉴权与身份识别
	VerifyKey(ctx context.Context, ak, sk string) (int64, error)
	// ListKeysByTenantID 检索指定租户下拥有的所有凭证列表，支持多凭证管理与轮转过渡
	ListKeysByTenantID(ctx context.Context, tenantID int64) ([]domain.TenantKey, error)
	// UpdateKeyStatus 启用或禁用指定的凭证，用于密钥泄露时的紧急停用或状态管理
	UpdateKeyStatus(ctx context.Context, id int64, status int) error

	// GenerateDiscoveryToken 为指定微服务生成专属资产同步令牌 (格式: eiam_sct_<hex>)
	GenerateDiscoveryToken(ctx context.Context, serviceName string) (string, error)
	// VerifyDiscoveryToken 校验资产同步令牌并返回其绑定的微服务标识
	VerifyDiscoveryToken(ctx context.Context, token string) (string, error)
}

type tenantKeyService struct {
	repo    repository.ITenantKeyRepository
	svcRepo repository.IServiceRepository
}

func NewTenantKeyService(r repository.ITenantKeyRepository, svcRepo repository.IServiceRepository) ITenantKeyService {
	return &tenantKeyService{repo: r, svcRepo: svcRepo}
}

func (s *tenantKeyService) GenerateKey(ctx context.Context, tenantID int64, description string) (domain.TenantKey, error) {
	ak, err := generateRandomHex(24)
	if err != nil {
		return domain.TenantKey{}, err
	}
	// 加个 AK 前缀以作标识，比如 AKc58f...
	accessKey := "AK" + ak

	sk, err := generateRandomHex(48)
	if err != nil {
		return domain.TenantKey{}, err
	}

	tk := domain.TenantKey{
		TenantID:    tenantID,
		AccessKey:   accessKey,
		SecretKey:   sk,
		Status:      1, // 默认启用
		Description: description,
	}

	id, err := s.repo.Create(ctx, tk)
	if err != nil {
		return domain.TenantKey{}, err
	}
	tk.ID = id
	return tk, nil
}

func (s *tenantKeyService) GetTenantIDByAccessKey(ctx context.Context, ak string) (int64, error) {
	tk, err := s.repo.FindByAccessKey(ctx, ak)
	if err != nil {
		return 0, err
	}
	// 如果凭证已被禁用，则不能用于鉴权和获取租户 ID
	if tk.Status != 1 {
		return 0, errs.ErrTenantKeyDisabled
	}
	return tk.TenantID, nil
}

func (s *tenantKeyService) VerifyKey(ctx context.Context, ak, sk string) (int64, error) {
	tk, err := s.repo.FindByAccessKey(ctx, ak)
	if err != nil {
		return 0, err
	}
	if tk.Status != 1 {
		return 0, errs.ErrTenantKeyDisabled
	}
	if tk.SecretKey != sk {
		return 0, errs.ErrInvalidTenantKey
	}
	return tk.TenantID, nil
}

func (s *tenantKeyService) ListKeysByTenantID(ctx context.Context, tenantID int64) ([]domain.TenantKey, error) {
	return s.repo.ListByTenantID(ctx, tenantID)
}

func (s *tenantKeyService) UpdateKeyStatus(ctx context.Context, id int64, status int) error {
	return s.repo.UpdateStatus(ctx, id, status)
}

// GenerateDiscoveryToken 为指定微服务生成专属资产同步令牌 (绑定系统租户 tenant_id=1)。
// 生成前会校验服务 code 必须在服务目录中已登记，防止随意生成无效服务名的 Token。
func (s *tenantKeyService) GenerateDiscoveryToken(ctx context.Context, serviceName string) (string, error) {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		return "", fmt.Errorf("微服务标识不能为空")
	}

	// NOTE: 系统级操作，豁免租户隔离
	ctx = gormx.IgnoreTenantContext(ctx)

	// 前置校验：服务 code 必须在服务目录中已登记，防止生成无效服务名的 Token
	if _, err := s.svcRepo.GetByCode(ctx, serviceName); err != nil {
		return "", fmt.Errorf("微服务 [%s] 在服务目录中不存在，请先完成注册: %w", serviceName, err)
	}

	randomPart, err := generateRandomHex(32)
	if err != nil {
		return "", fmt.Errorf("生成随机令牌失败: %w", err)
	}

	token := "eiam_sct_" + randomPart

	// 存入系统租户 (tenant_id = 1) 名下，description 标记服务绑定关系
	tk := domain.TenantKey{
		TenantID:    1,
		AccessKey:   token,
		SecretKey:   token, // 单值 Token 模式下 AccessKey 与 SecretKey 等同
		Status:      1,     // 启用
		Description: fmt.Sprintf("discovery:service:%s", serviceName),
	}

	if _, err := s.repo.Create(ctx, tk); err != nil {
		return "", fmt.Errorf("保存微服务令牌失败: %w", err)
	}

	return token, nil
}

// VerifyDiscoveryToken 校验资产同步令牌并返回其绑定的微服务标识
func (s *tenantKeyService) VerifyDiscoveryToken(ctx context.Context, token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errs.ErrInvalidToken
	}

	// 系统级凭据校验：显式豁免租户隔离
	ctx = gormx.IgnoreTenantContext(ctx)

	tk, err := s.repo.FindByAccessKey(ctx, token)
	if err != nil {
		return "", errs.ErrInvalidToken
	}

	if tk.Status != 1 {
		return "", errs.ErrTenantKeyDisabled
	}

	// 从 description 中解析出绑定的 service 标识: discovery:service:<name>
	const prefix = "discovery:service:"
	if !strings.HasPrefix(tk.Description, prefix) {
		return "", fmt.Errorf("凭据未绑定资产发现服务标识")
	}

	serviceName := strings.TrimPrefix(tk.Description, prefix)
	return serviceName, nil
}

// generateRandomHex 生成指定长度的十六进制随机字符串
func generateRandomHex(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

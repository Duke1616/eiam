package tenant

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
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
}

type tenantKeyService struct {
	repo repository.ITenantKeyRepository
}

func NewTenantKeyService(r repository.ITenantKeyRepository) ITenantKeyService {
	return &tenantKeyService{repo: r}
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

// generateRandomHex 生成指定长度的十六进制随机字符串
func generateRandomHex(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

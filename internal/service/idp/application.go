package idp

import (
	"context"
	crypto_rand "crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

// IService 下游接入应用 (OIDC/CAS/SAML 等统一应用中心) 的生命周期管理接口
type IService interface {
	// Create 创建新的接入应用并生成初次客户端密钥
	Create(ctx context.Context, app domain.Application) (domain.Application, error)
	// Update 更新接入应用基础信息与回调白名单
	Update(ctx context.Context, app domain.Application) error
	// ResetSecret 重置接入应用的客户端密钥并返回新明文
	ResetSecret(ctx context.Context, id int64) (string, error)
	// GetByID 根据主键 ID 查询应用详情
	GetByID(ctx context.Context, id int64) (domain.Application, error)
	// GetByClientID 根据客户端标识查询应用配置
	GetByClientID(ctx context.Context, clientID string) (domain.Application, error)
	// List 分页查询接入应用列表 (自动应用租户隔离与系统共享边界)
	List(ctx context.Context, offset, limit int) ([]domain.Application, int64, error)
	// Delete 删除接入应用
	Delete(ctx context.Context, id int64) error
}

type applicationService struct {
	repo repository.IApplicationRepository
}

// NewApplicationService 构造接入应用管理服务实例
func NewApplicationService(repo repository.IApplicationRepository) IService {
	return &applicationService{repo: repo}
}

func (s *applicationService) Create(ctx context.Context, app domain.Application) (domain.Application, error) {
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

	if err = app.SetSecret(rawSecret); err != nil {
		return domain.Application{}, fmt.Errorf("计算客户端密钥哈希失败: %w", err)
	}

	id, err := s.repo.Create(ctx, app)
	if err != nil {
		return domain.Application{}, err
	}

	app.ID = id
	app.ClientSecret = rawSecret
	return app, nil
}

func (s *applicationService) Update(ctx context.Context, app domain.Application) error {
	app.InitDefaultConfig()
	if err := app.Validate(); err != nil {
		return err
	}

	if _, err := s.repo.FindByID(ctx, app.ID); err != nil {
		return errs.ErrApplicationNotFound
	}

	return s.repo.Update(ctx, app)
}

func (s *applicationService) ResetSecret(ctx context.Context, id int64) (string, error) {
	if _, err := s.repo.FindByID(ctx, id); err != nil {
		return "", errs.ErrApplicationNotFound
	}

	newRawSecret, err := s.generateSecret()
	if err != nil {
		return "", fmt.Errorf("生成新密钥失败: %w", err)
	}

	var tempApp domain.Application
	if err = tempApp.SetSecret(newRawSecret); err != nil {
		return "", fmt.Errorf("计算新密钥哈希失败: %w", err)
	}

	if err = s.repo.UpdateSecret(ctx, id, tempApp.ClientSecretHash); err != nil {
		return "", err
	}

	return newRawSecret, nil
}

func (s *applicationService) GetByID(ctx context.Context, id int64) (domain.Application, error) {
	app, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return domain.Application{}, errs.ErrApplicationNotFound
	}
	return app, nil
}

func (s *applicationService) GetByClientID(ctx context.Context, clientID string) (domain.Application, error) {
	app, err := s.repo.FindByClientID(ctx, clientID)
	if err != nil {
		return domain.Application{}, errs.ErrApplicationNotFound
	}
	return app, nil
}

func (s *applicationService) List(ctx context.Context, offset, limit int) ([]domain.Application, int64, error) {
	var (
		apps  []domain.Application
		total int64
	)
	eg, gctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		var err error
		apps, err = s.repo.List(gctx, offset, limit)
		return err
	})

	eg.Go(func() error {
		var err error
		total, err = s.repo.Count(gctx)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, 0, err
	}

	return apps, total, nil
}

func (s *applicationService) Delete(ctx context.Context, id int64) error {
	if _, err := s.repo.FindByID(ctx, id); err != nil {
		return errs.ErrApplicationNotFound
	}
	return s.repo.Delete(ctx, id)
}

func (s *applicationService) generateSecret() (string, error) {
	return generateRandomString(32)
}

// generateRandomString 生成指定字节长度的高强度加密随机字符串（URL 安全 base64）
func generateRandomString(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := crypto_rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}


package cas

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/internal/service/idp/claims"
	"github.com/Duke1616/eiam/internal/service/tenant"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/gotomicro/ego/core/elog"
	"github.com/samber/lo"
)

var (
	ErrInvalidService       = errs.ErrCasInvalidService
	ErrTicketInvalid        = errs.ErrCasTicketInvalid
	ErrUserNotFound         = errs.ErrCasUserNotFound
	ErrServiceNotRegistered = errs.ErrCasServiceNotRegistered
)

// ICasService CAS 2.0 / 3.0 身份提供商核心服务接口
//
//go:generate mockgen -source=./service.go -package=casmocks -destination=./mocks/service.mock.go -typed ICasService
type ICasService interface {
	// GenerateTicket 为已登录用户针对指定 service 生成 ST-xxxx 凭据并暂存
	GenerateTicket(ctx context.Context, userID, tenantID int64, username, service string) (string, error)
	// ValidateTicket 校验 Service Ticket 并原子核销，成功后返回用户实体和属性信息
	ValidateTicket(ctx context.Context, ticket, service string) (*domain.CasValidationResult, error)
	// ValidatePlainText CAS 1.0 协议验证，返回 (isValid, username)
	ValidatePlainText(ctx context.Context, ticket, service string) (bool, string)
	// BuildSuccessXML 构造标准的 CAS 2.0 / 3.0 成功验证响应 XML
	BuildSuccessXML(result *domain.CasValidationResult) string
	// BuildFailureXML 构造标准的 CAS 验证失败响应 XML
	BuildFailureXML(code, message string) string
	// BuildSuccessJSON 构造标准的 CAS 3.0 成功验证响应 JSON
	BuildSuccessJSON(result *domain.CasValidationResult) *domain.CasJsonResponse
	// BuildFailureJSON 构造标准的 CAS 验证失败响应 JSON
	BuildFailureJSON(code, message string) *domain.CasJsonResponse
}

type casService struct {
	cache          cache.ICasCache
	claimsResolver claims.IClaimsResolver
	appRepo        repository.IApplicationRepository
	tenantSvc      tenant.ITenantService
	logger         *elog.Component
}

// NewCasService 构造 CAS 核心服务实例
func NewCasService(
	cache cache.ICasCache,
	claimsResolver claims.IClaimsResolver,
	appRepo repository.IApplicationRepository,
	tenantSvc tenant.ITenantService,
) ICasService {
	return &casService{
		cache:          cache,
		claimsResolver: claimsResolver,
		appRepo:        appRepo,
		tenantSvc:      tenantSvc,
		logger:         elog.DefaultLogger,
	}
}

// GenerateTicket 为已登录用户针对指定 service 生成 ST-xxxx 凭据并暂存
func (s *casService) GenerateTicket(ctx context.Context, userID, tenantID int64, username, service string) (string, error) {
	if tenantID > 0 && ctxutil.GetTenantID(ctx) <= 0 {
		ctx = ctxutil.WithTenantID(ctx, tenantID)
	}

	// 1. 安全白名单匹配与多租户跨租户准入防线校验
	app, err := s.validateServiceAndTenantAccess(ctx, userID, tenantID, service)
	if err != nil {
		return "", err
	}

	// 2. 动态自适应确定生效租户：
	// 若应用为独立业务租户应用，强制对齐该应用真实租户，确保验票时解析出目标租户属性；
	// 若应用为平台公共应用 (SystemTenantID)，优先沿用当前用户登录会话租户
	effectiveTenantID := app.TenantID
	if effectiveTenantID == ctxutil.SystemTenantID && tenantID > 0 {
		effectiveTenantID = tenantID
	}

	// 3. 签发票据并持久化暂存
	return s.issueTicket(ctx, userID, effectiveTenantID, username, service)
}

// validateServiceAndTenantAccess 校验目标服务是否在应用白名单中，并防范跨租户非法越权访问
func (s *casService) validateServiceAndTenantAccess(ctx context.Context, userID, currentTenantID int64, service string) (*domain.Application, error) {
	// 依托 DAO 层 Scopes(gormx.IgnoreTenant())，此处 FindAll 具备 IdP 全局白名单视野
	apps, err := s.appRepo.FindAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("查询接入应用白名单失败: %w", err)
	}

	// 1. 查找匹配 service 规则的应用
	app, ok := lo.Find(apps, func(a domain.Application) bool {
		return a.MatchesCasService(service) || a.HasRedirectURI(service)
	})
	if !ok {
		s.logger.Warn("拒绝未注册或不在白名单的 CAS 登录重定向",
			elog.Int64("user_id", userID),
			elog.Int64("current_tenant_id", currentTenantID),
			elog.String("service", service),
		)
		return nil, ErrServiceNotRegistered
	}

	// 2. 多租户安全准入防线：若应用属于具体业务租户，且用户当前处于其他租户空间，校验用户是否具备目标租户成员身份
	if app.TenantID != ctxutil.SystemTenantID && app.TenantID != currentTenantID {
		targetCtx := ctxutil.WithTenantID(ctx, app.TenantID)
		hasAccess, err := s.tenantSvc.CheckUserTenantAccess(targetCtx, userID)
		if err != nil || !hasAccess {
			s.logger.Warn("拦截未授权跨租户 CAS 登录请求",
				elog.Int64("user_id", userID),
				elog.Int64("app_tenant_id", app.TenantID),
				elog.Int64("session_tenant_id", currentTenantID),
				elog.String("service", service),
			)
			return nil, errs.ErrTenantAccessDenied
		}
	}

	return &app, nil
}

// issueTicket 生成密码学安全的随机票据并存入 TicketStore
func (s *casService) issueTicket(ctx context.Context, userID, tenantID int64, username, service string) (string, error) {
	randBytes := make([]byte, 24)
	if _, err := rand.Read(randBytes); err != nil {
		return "", fmt.Errorf("生成随机票据熵源失败: %w", err)
	}

	ticket := fmt.Sprintf("ST-%s", hex.EncodeToString(randBytes))
	data := domain.CasTicketData{
		Ticket:    ticket,
		UserID:    userID,
		TenantID:  tenantID,
		Username:  username,
		Service:   service,
		CreatedAt: time.Now(),
	}

	// CAS ST 标准存活时间 5 分钟 (基于 ITicketStore 泛型强类型存储)
	if err := s.cache.SaveTicket(ctx, ticket, data, 5*time.Minute); err != nil {
		return "", fmt.Errorf("存储 CAS 票据至缓存失败: %w", err)
	}

	return ticket, nil
}

// ValidateTicket 校验并一次性核销票据
func (s *casService) ValidateTicket(ctx context.Context, ticket, service string) (*domain.CasValidationResult, error) {
	if ticket == "" || service == "" {
		return nil, ErrTicketInvalid
	}

	data, err := s.cache.GetAndDelTicket(ctx, ticket)
	if err != nil {
		if errors.Is(err, cache.ErrCasTicketNotFound) {
			return nil, ErrTicketInvalid
		}
		return nil, fmt.Errorf("核销 CAS 票据失败: %w", err)
	}

	// 校验目标 service 与签发时的 service 是否匹配 (使用领域模型的 MatchesService 规范化比对)
	if !data.MatchesService(service) {
		s.logger.Warn("CAS 验票服务不匹配",
			elog.String("origin_service", data.Service),
			elog.String("req_service", service),
		)
		return nil, ErrInvalidService
	}

	// 委托 claims 统一身份声明模块解析用户属性与当前租户生效角色
	userClaims, err := s.claimsResolver.Resolve(ctx, claims.IdentityRef{
		TenantID: data.TenantID,
		UserID:   data.UserID,
		Username: data.Username,
	})
	if err != nil {
		return nil, fmt.Errorf("解析 CAS 身份声明失败: %w", err)
	}
	if userClaims.UserID == 0 {
		return nil, ErrUserNotFound
	}

	return &domain.CasValidationResult{
		User:       userClaims.ToUser(),
		Attributes: userClaims.ToCasAttributes(),
	}, nil
}

// ValidatePlainText CAS 1.0 协议验证支持
func (s *casService) ValidatePlainText(ctx context.Context, ticket, service string) (bool, string) {
	result, err := s.ValidateTicket(ctx, ticket, service)
	if err != nil || result == nil {
		return false, ""
	}
	return true, result.User.Username
}

// BuildSuccessXML 构造标准的 CAS 2.0 / 3.0 成功 XML (委托领域模型序列化)
func (s *casService) BuildSuccessXML(result *domain.CasValidationResult) string {
	resp := result.ToServiceResponse()
	output, err := resp.ToXML()
	if err != nil {
		s.logger.Error("序列化 CAS 成功响应 XML 失败", elog.FieldErr(err))
		return s.BuildFailureXML("INTERNAL_ERROR", "序列化 XML 异常")
	}
	return output
}

// BuildFailureXML 构造标准的 CAS 失败 XML
func (s *casService) BuildFailureXML(code, message string) string {
	resp := domain.NewCasFailureResponse(code, message)
	output, err := resp.ToXML()
	if err != nil {
		return fmt.Sprintf("<cas:serviceResponse xmlns:cas='%s'><cas:authenticationFailure code='%s'>%s</cas:authenticationFailure></cas:serviceResponse>",
			domain.CasXMLNamespace, code, message)
	}
	return output
}

// BuildSuccessJSON 构造标准的 CAS 3.0 成功 JSON 响应 (委托领域模型构造)
func (s *casService) BuildSuccessJSON(result *domain.CasValidationResult) *domain.CasJsonResponse {
	resp := result.ToJsonResponse()
	return &resp
}

// BuildFailureJSON 构造标准的 CAS 3.0 失败 JSON 响应
func (s *casService) BuildFailureJSON(code, message string) *domain.CasJsonResponse {
	resp := domain.NewCasFailureJsonResponse(code, message)
	return &resp
}

package cas

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/internal/repository/cache"
	repomocks "github.com/Duke1616/eiam/internal/repository/mocks"
	"github.com/Duke1616/eiam/internal/service/idp/claims"
	claimsmocks "github.com/Duke1616/eiam/internal/service/idp/claims/mocks"
	tenantmocks "github.com/Duke1616/eiam/internal/service/tenant/mocks"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// mockCasCache 简单的内存模拟 Cache
type mockCasCache struct {
	store map[string]domain.CasTicketData
}

func newMockCasCache() *mockCasCache {
	return &mockCasCache{store: make(map[string]domain.CasTicketData)}
}

func (m *mockCasCache) SaveTicket(ctx context.Context, ticket string, data domain.CasTicketData, ttl time.Duration) error {
	m.store[ticket] = data
	return nil
}

func (m *mockCasCache) GetAndDelTicket(ctx context.Context, ticket string) (domain.CasTicketData, error) {
	val, ok := m.store[ticket]
	if !ok {
		return domain.CasTicketData{}, cache.ErrCasTicketNotFound
	}
	delete(m.store, ticket) // 原子核销模拟
	return val, nil
}

func TestCasService_GenerateAndValidateTicket(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	claimsResolver := claimsmocks.NewMockIClaimsResolver(ctrl)
	clientRepo := repomocks.NewMockIApplicationRepository(ctrl)
	tenantSvc := tenantmocks.NewMockITenantService(ctrl)
	c := newMockCasCache()

	svc := NewCasService(c, claimsResolver, clientRepo, tenantSvc)

	ctx := context.Background()
	serviceURL := "https://example.com/core/auth/cas/login/?next=%2Fui%2F"

	// 1. 测试应用白名单未注册场景
	clientRepo.EXPECT().FindAll(gomock.Any()).Return([]domain.Application{
		{
			ID:           1,
			TenantID:     ctxutil.SystemTenantID,
			Name:         "GitLab",
			RedirectURIs: []string{"https://gitlab.example.com/callback"},
		},
	}, nil)
	_, err := svc.GenerateTicket(ctx, 1001, 1, "admin", serviceURL)
	assert.True(t, errors.Is(err, ErrServiceNotRegistered))

	// 1.1 测试跨租户越权访问拦截：用户当前处于租户 3，应用归属租户 2，用户无租户 2 访问权限
	clientRepo.EXPECT().FindAll(gomock.Any()).Return([]domain.Application{
		{
			ID:           2,
			TenantID:     2,
			Name:         "JumpServer堡垒机",
			RedirectURIs: []string{"https://example.com/core/auth/cas/login/"},
		},
	}, nil)
	tenantSvc.EXPECT().CheckUserTenantAccess(gomock.Any(), int64(1001)).Return(false, nil)
	_, err = svc.GenerateTicket(ctx, 1001, 3, "admin", serviceURL)
	assert.True(t, errors.Is(err, errs.ErrTenantAccessDenied))

	// 1.2 测试跨租户合法放行：用户当前处于租户 3，应用归属租户 2，用户拥有租户 2 权限 -> 放行且 Ticket 绑定租户 2
	clientRepo.EXPECT().FindAll(gomock.Any()).Return([]domain.Application{
		{
			ID:           2,
			TenantID:     2,
			Name:         "JumpServer堡垒机",
			RedirectURIs: []string{"https://example.com/core/auth/cas/login/"},
		},
	}, nil)
	tenantSvc.EXPECT().CheckUserTenantAccess(gomock.Any(), int64(1001)).Return(true, nil)
	crossTicket, err := svc.GenerateTicket(ctx, 1001, 3, "admin", serviceURL)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(crossTicket, "ST-"))
	assert.Equal(t, int64(2), c.store[crossTicket].TenantID)

	// 2. 测试同租户直接放行 (应用在租户 2，用户当前会话也在租户 2，0 额外开销直接放行)
	clientRepo.EXPECT().FindAll(gomock.Any()).Return([]domain.Application{
		{
			ID:           2,
			TenantID:     2,
			Name:         "JumpServer堡垒机",
			RedirectURIs: []string{"https://example.com/core/auth/cas/login/"},
		},
	}, nil)
	ticket, err := svc.GenerateTicket(ctx, 1001, 2, "admin", serviceURL)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ticket, "ST-"))

	// 3. 验证 Service 不匹配
	_, err = svc.ValidateTicket(ctx, ticket, "https://another-system.example.com/callback")
	assert.True(t, errors.Is(err, ErrInvalidService))

	// 因为上一轮失败，但票据已被核销（一次性凭据安全机制），下一轮再次验证应当返回 ErrTicketInvalid
	_, err = svc.ValidateTicket(ctx, ticket, serviceURL)
	assert.True(t, errors.Is(err, ErrTicketInvalid))

	// 4. 重新生成 Ticket 进行成功链路校验
	clientRepo.EXPECT().FindAll(gomock.Any()).Return([]domain.Application{
		{
			ID:           2,
			TenantID:     ctxutil.SystemTenantID,
			Name:         "JumpServer堡垒机",
			RedirectURIs: []string{"https://example.com/core/auth/cas/login/"},
		},
	}, nil)
	ticket2, err := svc.GenerateTicket(ctx, 1001, 2, "admin", serviceURL)
	require.NoError(t, err)

	claimsResolver.EXPECT().Resolve(gomock.Any(), claims.IdentityRef{TenantID: 2, UserID: 1001, Username: "admin"}).Return(claims.Claims{
		Subject:  "1001",
		UserID:   1001,
		Username: "admin",
		Name:     "系统管理员",
		Nickname: "系统管理员",
		Email:    "admin@example.com",
		Phone:    "13800138000",
		TenantID: 2,
	}, nil)

	result, err := svc.ValidateTicket(ctx, ticket2, serviceURL)
	require.NoError(t, err)
	assert.Equal(t, "admin", result.User.Username)
	assert.Equal(t, "admin@example.com", result.Attributes["email"])
	assert.Equal(t, "系统管理员", result.Attributes["name"])
	assert.Equal(t, int64(2), result.Attributes["tenant_id"])

	// 5. 验证生成的 CAS 2.0 / 3.0 XML 响应结构
	xmlSuccess := svc.BuildSuccessXML(result)
	assert.Contains(t, xmlSuccess, "<cas:authenticationSuccess>")
	assert.Contains(t, xmlSuccess, "<cas:user>admin</cas:user>")
	assert.Contains(t, xmlSuccess, "<cas:email>admin@example.com</cas:email>")
	assert.Contains(t, xmlSuccess, "<cas:name>系统管理员</cas:name>")

	// 6. 验证失败 XML
	xmlFailure := svc.BuildFailureXML("INVALID_TICKET", "票据已被使用")
	assert.Contains(t, xmlFailure, "code=\"INVALID_TICKET\"")
	assert.Contains(t, xmlFailure, "票据已被使用")

	// 7. 验证 CAS 1.0 纯文本协议支持
	clientRepo.EXPECT().FindAll(gomock.Any()).Return([]domain.Application{
		{
			ID:           2,
			TenantID:     ctxutil.SystemTenantID,
			Name:         "JumpServer堡垒机",
			RedirectURIs: []string{"https://example.com/core/auth/cas/login/"},
		},
	}, nil)
	ticket3, err := svc.GenerateTicket(ctx, 1001, ctxutil.SystemTenantID, "admin", serviceURL)
	require.NoError(t, err)
	claimsResolver.EXPECT().Resolve(gomock.Any(), claims.IdentityRef{TenantID: ctxutil.SystemTenantID, UserID: 1001, Username: "admin"}).Return(claims.Claims{
		UserID:   1001,
		Username: "admin",
	}, nil)
	ok, username := svc.ValidatePlainText(ctx, ticket3, serviceURL)
	assert.True(t, ok)
	assert.Equal(t, "admin", username)

	// 8. 验证 CAS 3.0 JSON 响应构建
	jsonSuccess := svc.BuildSuccessJSON(result)
	assert.Equal(t, "admin", jsonSuccess.ServiceResponse.AuthenticationSuccess.User)
	assert.Equal(t, "admin@example.com", jsonSuccess.ServiceResponse.AuthenticationSuccess.Attributes["email"])

	jsonFailure := svc.BuildFailureJSON("INVALID_TICKET", "票据错误")
	assert.Equal(t, "INVALID_TICKET", jsonFailure.ServiceResponse.AuthenticationFailure.Code)
	assert.Equal(t, "票据错误", jsonFailure.ServiceResponse.AuthenticationFailure.Description)
}

package cas

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository/cache"
	repomocks "github.com/Duke1616/eiam/internal/repository/mocks"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// mockCasCache 简单的内存模拟 Cache
type mockCasCache struct {
	store map[string][]byte
}

func newMockCasCache() *mockCasCache {
	return &mockCasCache{store: make(map[string][]byte)}
}

func (m *mockCasCache) SaveTicket(ctx context.Context, ticket string, data []byte, ttl time.Duration) error {
	m.store[ticket] = data
	return nil
}

func (m *mockCasCache) GetAndDelTicket(ctx context.Context, ticket string) ([]byte, error) {
	val, ok := m.store[ticket]
	if !ok {
		return nil, cache.ErrCasTicketNotFound
	}
	delete(m.store, ticket) // 原子核销模拟
	return val, nil
}

func TestCasService_GenerateAndValidateTicket(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	userRepo := repomocks.NewMockIUserRepository(ctrl)
	clientRepo := repomocks.NewMockIApplicationRepository(ctrl)
	c := newMockCasCache()

	svc := NewCasService(c, userRepo, clientRepo)

	ctx := context.Background()
	serviceURL := "https://jumpserver.local/core/auth/cas/callback/"

	// 1. 测试应用白名单未注册场景
	clientRepo.EXPECT().ListByTenantID(gomock.Any(), int64(1), 0, 100).Return([]domain.Application{
		{
			ID:           1,
			TenantID:     1,
			Name:         "GitLab",
			RedirectURIs: []string{"https://gitlab.local/callback"},
		},
	}, int64(1), nil)
	_, err := svc.GenerateTicket(ctx, 1001, 1, "admin", serviceURL)
	assert.True(t, errors.Is(err, ErrServiceNotRegistered))

	// 2. 测试应用白名单命中，成功生成 Ticket
	clientRepo.EXPECT().ListByTenantID(gomock.Any(), int64(1), 0, 100).Return([]domain.Application{
		{
			ID:           2,
			TenantID:     1,
			Name:         "JumpServer堡垒机",
			RedirectURIs: []string{serviceURL},
		},
	}, int64(1), nil)
	ticket, err := svc.GenerateTicket(ctx, 1001, 1, "admin", serviceURL)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ticket, "ST-"))

	// 3. 验证 Service 不匹配
	_, err = svc.ValidateTicket(ctx, ticket, "https://another-system.local/callback")
	assert.True(t, errors.Is(err, ErrInvalidService))

	// 因为上一轮失败，但票据已被核销（一次性凭据安全机制），下一轮再次验证应当返回 ErrTicketInvalid
	_, err = svc.ValidateTicket(ctx, ticket, serviceURL)
	assert.True(t, errors.Is(err, ErrTicketInvalid))

	// 3. 重新生成 Ticket 进行成功链路校验
	clientRepo.EXPECT().ListByTenantID(gomock.Any(), int64(1), 0, 100).Return([]domain.Application{
		{
			ID:           2,
			TenantID:     1,
			Name:         "JumpServer堡垒机",
			RedirectURIs: []string{serviceURL},
		},
	}, int64(1), nil)
	ticket2, err := svc.GenerateTicket(ctx, 1001, 1, "admin", serviceURL)
	require.NoError(t, err)

	userRepo.EXPECT().FindById(gomock.Any(), int64(1001)).DoAndReturn(
		func(c context.Context, id int64) (domain.User, error) {
			// 验证租户上下文已正确绑定注入
			assert.Equal(t, int64(1), ctxutil.GetTenantID(c).Int64())
			return domain.User{
				ID:       1001,
				Username: "admin",
				Email:    "admin@example.com",
				Profile: domain.UserProfile{
					Nickname: "系统管理员",
					Phone:    "13800138000",
				},
			}, nil
		},
	)

	result, err := svc.ValidateTicket(ctx, ticket2, serviceURL)
	require.NoError(t, err)
	assert.Equal(t, "admin", result.User.Username)
	assert.Equal(t, "admin@example.com", result.Attributes["email"])
	assert.Equal(t, "系统管理员", result.Attributes["name"])

	// 4. 验证生成的 CAS 2.0 / 3.0 XML 响应结构
	xmlSuccess := svc.BuildSuccessXML(result)
	assert.Contains(t, xmlSuccess, "<cas:authenticationSuccess>")
	assert.Contains(t, xmlSuccess, "<cas:user>admin</cas:user>")
	assert.Contains(t, xmlSuccess, "<cas:email>admin@example.com</cas:email>")
	assert.Contains(t, xmlSuccess, "<cas:name>系统管理员</cas:name>")

	// 5. 验证失败 XML
	xmlFailure := svc.BuildFailureXML("INVALID_TICKET", "票据已被使用")
	assert.Contains(t, xmlFailure, "code=\"INVALID_TICKET\"")
	assert.Contains(t, xmlFailure, "票据已被使用")

	// 6. 验证 CAS 1.0 纯文本协议支持
	clientRepo.EXPECT().ListByTenantID(gomock.Any(), int64(1), 0, 100).Return([]domain.Application{
		{
			ID:           2,
			TenantID:     1,
			Name:         "JumpServer堡垒机",
			RedirectURIs: []string{serviceURL},
		},
	}, int64(1), nil)
	ticket3, err := svc.GenerateTicket(ctx, 1001, 1, "admin", serviceURL)
	require.NoError(t, err)
	userRepo.EXPECT().FindById(gomock.Any(), int64(1001)).Return(domain.User{
		ID:       1001,
		Username: "admin",
	}, nil)
	ok, username := svc.ValidatePlainText(ctx, ticket3, serviceURL)
	assert.True(t, ok)
	assert.Equal(t, "admin", username)

	// 7. 验证 CAS 3.0 JSON 响应构建
	jsonSuccess := svc.BuildSuccessJSON(result)
	assert.Equal(t, "admin", jsonSuccess.ServiceResponse.AuthenticationSuccess.User)
	assert.Equal(t, "admin@example.com", jsonSuccess.ServiceResponse.AuthenticationSuccess.Attributes["email"])

	jsonFailure := svc.BuildFailureJSON("INVALID_TICKET", "票据错误")
	assert.Equal(t, "INVALID_TICKET", jsonFailure.ServiceResponse.AuthenticationFailure.Code)
	assert.Equal(t, "票据错误", jsonFailure.ServiceResponse.AuthenticationFailure.Description)

	// 8. 验证多租户全局应用(tenant_id=1)白名单 Fallback
	clientRepo.EXPECT().ListByTenantID(gomock.Any(), int64(10), 0, 100).Return(nil, int64(0), nil) // 当前租户10未配置
	clientRepo.EXPECT().ListByTenantID(gomock.Any(), int64(1), 0, 100).Return([]domain.Application{   // 根租户1配置了全局JumpServer
		{
			ID:           99,
			TenantID:     1,
			Name:         "企业全局JumpServer",
			RedirectURIs: []string{serviceURL},
		},
	}, int64(1), nil)
	ticketFallback, err := svc.GenerateTicket(ctx, 2002, 10, "bob", serviceURL)
	require.NoError(t, err)
	assert.NotEmpty(t, ticketFallback)
}

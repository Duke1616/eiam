package identity_source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/coreos/go-oidc/v3/oidc"
	lark "github.com/larksuite/oapi-sdk-go/v3"
	"golang.org/x/oauth2"
)

type OidcService interface {
	// AuthURL 生成授权跳转地址 (带 nonce)
	AuthURL(ctx context.Context, config domain.OIDCConfig, state string, nonce string) (string, error)
	// Verify 校验回调 Code 并返回身份信息 (含 nonce 校验)
	Verify(ctx context.Context, source domain.IdentitySource, code string, nonce string) (domain.OidcIdentity, error)
}

type oidcService struct {
	// providers 并发安全的 Provider 实例缓存池 (Key: Issuer URL, Value: *oidc.Provider)
	// 避免每次请求都向外部 IdP 发起 Discovery 远程拉取，复用底层 JWKS 公钥缓存
	providers  sync.Map
	httpClient *http.Client
}

// NewOidcService 构造 OIDC 业务服务，初始化高可用 HTTP 连接池
func NewOidcService() OidcService {
	return &oidcService{
		httpClient: &http.Client{
			Timeout: 10 * time.Second, // 强制设置超时防外部接口假死
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (s *oidcService) AuthURL(ctx context.Context, conf domain.OIDCConfig, state string, nonce string) (string, error) {
	client, err := s.newOIDCClient(ctx, conf)
	if err != nil {
		return "", err
	}
	return client.AuthCodeURL(state, nonce), nil
}

func (s *oidcService) Verify(ctx context.Context, source domain.IdentitySource, code string, nonce string) (domain.OidcIdentity, error) {
	client, err := s.newOIDCClient(ctx, source.OIDCConfig)
	if err != nil {
		return domain.OidcIdentity{}, err
	}

	token, err := client.Exchange(ctx, code)
	if err != nil {
		return domain.OidcIdentity{}, fmt.Errorf("token 交换失败: %w", err)
	}

	claims, err := client.ResolveClaims(ctx, token, nonce)
	if err != nil {
		return domain.OidcIdentity{}, err
	}

	identity, err := client.mapper().Map(source.ID, claims)
	if err != nil {
		return domain.OidcIdentity{}, err
	}

	// 根据配置填充来源信息
	identity.SourceType = domain.OIDC
	identity.Provider = resolveProviderName(source.OIDCConfig)

	return identity, nil
}

// getOrCreateProvider 从内存缓存池获取或发现 OIDC 提供商，自动适配内网 HTTP 协议
func (s *oidcService) getOrCreateProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	if val, ok := s.providers.Load(issuer); ok {
		return val.(*oidc.Provider), nil
	}

	// 注入带超时的连接池 Client
	clientCtx := oidc.ClientContext(ctx, s.httpClient)

	provider, err := oidc.NewProvider(clientCtx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC 提供商连接与 Discovery 失败: %w", err)
	}

	// 存入缓存池供后续鉴权复用
	s.providers.Store(issuer, provider)
	return provider, nil
}

type AuthStrategy interface {
	AuthCodeURL(state string, nonce string) string
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	ResolveClaims(ctx context.Context, token *oauth2.Token, nonce string) (map[string]interface{}, error)
}

type oidcClient struct {
	service  *oidcService
	conf     domain.OIDCConfig
	provider *oidc.Provider
	oauth2   oauth2.Config
	strategy AuthStrategy
}

func (s *oidcService) newOIDCClient(ctx context.Context, conf domain.OIDCConfig) (*oidcClient, error) {
	client := &oidcClient{
		service: s,
		conf:    conf,
	}

	// 优先使用手动端点（飞书等国内 OAuth2 提供商）
	if conf.AuthURL != "" && conf.TokenURL != "" {
		client.oauth2 = oauth2.Config{
			ClientID:     conf.ClientID,
			ClientSecret: conf.ClientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  conf.AuthURL,
				TokenURL: conf.TokenURL,
			},
			RedirectURL: conf.RedirectURI,
			Scopes:      conf.Scopes,
		}

		if conf.ProviderType == domain.OIDCProviderFeishu {
			sdkClient := lark.NewClient(conf.ClientID, conf.ClientSecret)
			client.strategy = &feishuStrategy{client: client, sdk: sdkClient}
		} else {
			client.strategy = &standardStrategy{client: client}
		}
		return client, nil
	}

	// 标准 OIDC：通过并发安全缓存池获取 Provider，避免重复 Discovery 网络开销
	provider, err := s.getOrCreateProvider(ctx, conf.Issuer)
	if err != nil {
		return nil, err
	}

	client.provider = provider
	client.oauth2 = oauth2.Config{
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  conf.RedirectURI,
		Scopes:       conf.Scopes,
	}
	client.strategy = &standardStrategy{client: client}
	return client, nil
}

func (c *oidcClient) AuthCodeURL(state string, nonce string) string {
	return c.strategy.AuthCodeURL(state, nonce)
}

func (c *oidcClient) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return c.strategy.Exchange(ctx, code)
}

func (c *oidcClient) ResolveClaims(ctx context.Context, token *oauth2.Token, nonce string) (map[string]interface{}, error) {
	return c.strategy.ResolveClaims(ctx, token, nonce)
}

func (s *oidcService) fetchUserInfoByURL(ctx context.Context, token *oauth2.Token, userInfoURL string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("构造 UserInfo 请求失败: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	// 使用具备超时与连接池管理的专属 httpClient
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 UserInfo 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("UserInfo 返回异常状态码: %d", resp.StatusCode)
	}

	var payload map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("解析 UserInfo 响应失败: %w", err)
	}

	return unwrapClaims(payload), nil
}

// 保持包级别包装兼容
func fetchUserInfoByURL(ctx context.Context, token *oauth2.Token, userInfoURL string) (map[string]interface{}, error) {
	service := NewOidcService().(*oidcService)
	return service.fetchUserInfoByURL(ctx, token, userInfoURL)
}

func unwrapClaims(payload map[string]interface{}) map[string]interface{} {
	if data, ok := payload["data"].(map[string]interface{}); ok && len(data) > 0 {
		return data
	}
	return payload
}

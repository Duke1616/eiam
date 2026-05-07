package identity_source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

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

type oidcService struct{}

func NewOidcService() OidcService {
	return &oidcService{}
}

func (s *oidcService) AuthURL(ctx context.Context, conf domain.OIDCConfig, state string, nonce string) (string, error) {
	client, err := newOIDCClient(ctx, conf)
	if err != nil {
		return "", err
	}
	return client.AuthCodeURL(state, nonce), nil
}

func (s *oidcService) Verify(ctx context.Context, source domain.IdentitySource, code string, nonce string) (domain.OidcIdentity, error) {
	client, err := newOIDCClient(ctx, source.OIDCConfig)
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

type AuthStrategy interface {
	AuthCodeURL(state string, nonce string) string
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	ResolveClaims(ctx context.Context, token *oauth2.Token, nonce string) (map[string]interface{}, error)
}

type oidcClient struct {
	conf     domain.OIDCConfig
	provider *oidc.Provider
	oauth2   oauth2.Config
	strategy AuthStrategy
}

func newOIDCClient(ctx context.Context, conf domain.OIDCConfig) (*oidcClient, error) {
	client := &oidcClient{conf: conf}

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

	// 标准 OIDC：通过 Discovery 获取端点
	provider, err := oidc.NewProvider(ctx, conf.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC 提供商连接失败: %w", err)
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

func fetchUserInfoByURL(ctx context.Context, token *oauth2.Token, userInfoURL string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("构造 UserInfo 请求失败: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
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

func unwrapClaims(payload map[string]interface{}) map[string]interface{} {
	if data, ok := payload["data"].(map[string]interface{}); ok && len(data) > 0 {
		return data
	}
	return payload
}

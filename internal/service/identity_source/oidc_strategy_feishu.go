package identity_source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	lark "github.com/larksuite/oapi-sdk-go/v3"
	larkcore "github.com/larksuite/oapi-sdk-go/v3/core"
	larkauthen "github.com/larksuite/oapi-sdk-go/v3/service/authen/v1"
	"golang.org/x/oauth2"
)

type feishuStrategy struct {
	client *oidcClient
	sdk    *lark.Client
}

func (s *feishuStrategy) AuthCodeURL(state string, nonce string) string {
	parsedURL, err := url.Parse(s.client.conf.AuthURL)
	if err != nil {
		return s.client.conf.AuthURL
	}

	q := parsedURL.Query()
	q.Set("client_id", s.client.conf.ClientID)
	q.Set("redirect_uri", s.client.conf.RedirectURI)
	q.Set("response_type", "code")

	if state != "" {
		q.Set("state", state)
	}

	parsedURL.RawQuery = q.Encode()
	return parsedURL.String()
}

func (s *feishuStrategy) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	req := larkauthen.NewCreateAccessTokenReqBuilder().
		Body(larkauthen.NewCreateAccessTokenReqBodyBuilder().
			GrantType(`authorization_code`).
			Code(code).
			Build()).
		Build()

	resp, err := s.sdk.Authen.AccessToken.Create(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("调用飞书 SDK 获取 AccessToken 发生异常: %w", err)
	}

	if !resp.Success() {
		return nil, fmt.Errorf("飞书获取 user_access_token 失败: %d %s", resp.Code, resp.Msg)
	}

	return &oauth2.Token{
		AccessToken: *resp.Data.AccessToken,
		TokenType:   *resp.Data.TokenType,
		Expiry:      time.Now().Add(time.Duration(*resp.Data.ExpiresIn) * time.Second),
	}, nil
}

func (s *feishuStrategy) ResolveClaims(ctx context.Context, token *oauth2.Token, nonce string) (map[string]interface{}, error) {
	resp, err := s.sdk.Authen.UserInfo.Get(ctx, larkcore.WithUserAccessToken(token.AccessToken))
	if err != nil {
		return nil, fmt.Errorf("调用飞书 SDK 获取 UserInfo 发生异常: %w", err)
	}

	if !resp.Success() {
		return nil, fmt.Errorf("飞书获取 UserInfo 失败: %d %s", resp.Code, resp.Msg)
	}

	b, _ := json.Marshal(resp.Data)
	var claims map[string]interface{}
	_ = json.Unmarshal(b, &claims)

	if len(claims) == 0 {
		return nil, fmt.Errorf("飞书 OIDC 身份信息为空")
	}
	return claims, nil
}

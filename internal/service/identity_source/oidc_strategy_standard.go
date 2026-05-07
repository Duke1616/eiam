package identity_source

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type standardStrategy struct {
	client *oidcClient
}

func (s *standardStrategy) AuthCodeURL(state string, nonce string) string {
	return s.client.oauth2.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce))
}

func (s *standardStrategy) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return s.client.oauth2.Exchange(ctx, code)
}

func (s *standardStrategy) ResolveClaims(ctx context.Context, token *oauth2.Token, nonce string) (map[string]interface{}, error) {
	if claims, err := s.resolveIDTokenClaims(ctx, token, nonce); err != nil {
		return nil, err
	} else if len(claims) > 0 {
		return claims, nil
	}

	claims, err := s.resolveUserInfoClaims(ctx, token)
	if err != nil {
		return nil, err
	}
	if len(claims) == 0 {
		return nil, fmt.Errorf("OIDC 身份信息为空")
	}
	return claims, nil
}

func (s *standardStrategy) resolveIDTokenClaims(ctx context.Context, token *oauth2.Token, nonce string) (map[string]interface{}, error) {
	if s.client.provider == nil {
		return nil, nil
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, nil
	}

	verifier := s.client.provider.Verifier(&oidc.Config{ClientID: s.client.conf.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("ID Token 校验失败: %w", err)
	}

	if idToken.Nonce != nonce {
		return nil, fmt.Errorf("ID Token nonce 校验失败: 期望 %s, 实际 %s", nonce, idToken.Nonce)
	}

	claims := make(map[string]interface{})
	if err = idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("解析 Claims 失败: %w", err)
	}
	return claims, nil
}

func (s *standardStrategy) resolveUserInfoClaims(ctx context.Context, token *oauth2.Token) (map[string]interface{}, error) {
	if s.client.conf.UserInfoURL != "" {
		return fetchUserInfoByURL(ctx, token, s.client.conf.UserInfoURL)
	}

	if s.client.provider == nil {
		return nil, fmt.Errorf("未配置 UserInfoURL，无法获取用户信息")
	}

	userInfo, err := s.client.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		return nil, fmt.Errorf("获取 UserInfo 失败: %w", err)
	}

	claims := make(map[string]interface{})
	if err := userInfo.Claims(&claims); err != nil {
		return nil, fmt.Errorf("解析 UserInfo 失败: %w", err)
	}
	return claims, nil
}

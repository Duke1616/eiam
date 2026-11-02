package grant

import (
	"context"
	"errors"
	"testing"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type mockKeySigner struct {
	signFn func(claims jwt.Claims) (string, error)
}

func (m *mockKeySigner) SignJWT(claims jwt.Claims) (string, error) {
	if m.signFn != nil {
		return m.signFn(claims)
	}
	return "mocked.jwt.token", nil
}

func TestClientCredentialsGrantHandler_TableDriven(t *testing.T) {
	ctx := context.Background()

	rawSecret := "valid-secret-123"
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte(rawSecret), bcrypt.DefaultCost)

	baseApp := domain.Application{
		ClientID:         "m2m-service-client",
		ClientSecretHash: string(hashedSecret),
		Name:             "M2M Service",
		TenantID:         100,
		Scopes:           []string{"read", "write"},
		GrantTypes:       []string{"client_credentials"},
	}

	testCases := []struct {
		name          string
		req           domain.TokenRequest
		app           domain.Application
		signer        IKeySigner
		expectedErr   error
		verifyResult  func(t *testing.T, res *domain.OidcTokenResult)
		expectSecLogs bool
	}{
		{
			name: "成功签发 M2M Access Token (不签发 refresh_token 与 id_token)",
			req: domain.TokenRequest{
				GrantType:    "client_credentials",
				ClientID:     "m2m-service-client",
				ClientSecret: "valid-secret-123",
				Scope:        "read",
			},
			app: baseApp,
			signer: &mockKeySigner{
				signFn: func(claims jwt.Claims) (string, error) {
					idClaims, ok := claims.(domain.IDTokenClaims)
					require.True(t, ok)
					assert.Equal(t, "m2m-service-client", idClaims.Subject)
					assert.Equal(t, int64(100), idClaims.TenantID)
					return "mocked.m2m.access.token", nil
				},
			},
			verifyResult: func(t *testing.T, res *domain.OidcTokenResult) {
				assert.Equal(t, "mocked.m2m.access.token", res.AccessToken)
				assert.Equal(t, "Bearer", res.TokenType)
				assert.Equal(t, int64(7200), res.ExpiresIn)
				assert.Equal(t, "read", res.Scope)
				assert.Empty(t, res.RefreshToken, "RFC 6749 规定客户端模式不得签发 refresh_token")
				assert.Empty(t, res.IDToken, "RFC 6749 规定客户端模式无自然人用户，不得签发 id_token")
			},
		},
		{
			name: "密钥错误拒绝签发并记录安全审计",
			req: domain.TokenRequest{
				GrantType:    "client_credentials",
				ClientID:     "m2m-service-client",
				ClientSecret: "wrong-secret",
			},
			app:           baseApp,
			signer:        &mockKeySigner{},
			expectedErr:   errs.ErrApplicationSecretWrong,
			expectSecLogs: true,
		},
		{
			name: "JWT签名异常返回错误",
			req: domain.TokenRequest{
				GrantType:    "client_credentials",
				ClientID:     "m2m-service-client",
				ClientSecret: "valid-secret-123",
			},
			app: baseApp,
			signer: &mockKeySigner{
				signFn: func(claims jwt.Claims) (string, error) {
					return "", errors.New("private key signing failed")
				},
			},
			expectedErr: errors.New("签发 M2M 机器 Access Token 失败"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var secLogged bool
			secLogFn := func(ctx context.Context, app domain.Application, action, failReason string) {
				secLogged = true
				assert.Equal(t, "client_credentials", action)
			}

			handler := NewClientCredentialsGrantHandler(tc.signer, secLogFn)
			assert.Equal(t, "client_credentials", handler.GrantType())

			res, err := handler.Handle(ctx, tc.req, tc.app, "http://localhost:9000")

			if tc.expectedErr != nil {
				assert.Error(t, err)
				assert.Nil(t, res)
				if tc.expectSecLogs {
					assert.True(t, secLogged, "预期应触发安全审计日志")
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, res)
				if tc.verifyResult != nil {
					tc.verifyResult(t, res)
				}
			}
		})
	}
}

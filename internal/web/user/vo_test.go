package user

import (
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/require"
)

func TestPasskeyStartResponsesKeepPublicKeyEnvelope(t *testing.T) {
	testCases := []struct {
		name     string
		response any
	}{
		{
			name: "注册选项",
			response: PasskeyRegisterStartResponse{
				Options: &protocol.CredentialCreation{Response: protocol.PublicKeyCredentialCreationOptions{
					Challenge: protocol.URLEncodedBase64("register-challenge"),
				}},
				SessionToken: "register-session",
			},
		},
		{
			name: "登录选项",
			response: PasskeyLoginStartResponse{
				Options: &protocol.CredentialAssertion{Response: protocol.PublicKeyCredentialRequestOptions{
					Challenge: protocol.URLEncodedBase64("login-challenge"),
				}},
				SessionToken: "login-session",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			payload, err := json.Marshal(testCase.response)
			require.NoError(t, err)

			var decoded map[string]any
			require.NoError(t, json.Unmarshal(payload, &decoded))
			options, ok := decoded["options"].(map[string]any)
			require.True(t, ok)
			publicKey, ok := options["publicKey"].(map[string]any)
			require.True(t, ok)
			require.NotEmpty(t, publicKey["challenge"])
			require.NotEmpty(t, decoded["session_token"])
		})
	}
}

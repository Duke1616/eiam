package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOAuthClient_HasRedirectURI(t *testing.T) {
	client := OAuthClient{
		RedirectURIs: []string{
			"https://git.ebondhm.com/users/auth/openid_connect/callback",
			"https://gitlab.ebondhm.com/users/auth/openid_connect/callback",
			"http://localhost:3000/callback",
		},
	}

	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "精确匹配",
			input:    "https://git.ebondhm.com/users/auth/openid_connect/callback",
			expected: true,
		},
		{
			name:     "二次 URL 编码容错匹配",
			input:    "https%3A%2F%2Fgit.ebondhm.com%2Fusers%2Fauth%2Fopenid_connect%2Fcallback",
			expected: true,
		},
		{
			name:     "尾部斜杠容错匹配",
			input:    "https://git.ebondhm.com/users/auth/openid_connect/callback/",
			expected: true,
		},
		{
			name:     "本地 localhost 动态端口匹配",
			input:    "http://localhost:8080/callback",
			expected: true,
		},
		{
			name:     "非法 Fragment 阻断",
			input:    "https://git.ebondhm.com/users/auth/openid_connect/callback#token=123",
			expected: false,
		},
		{
			name:     "非白名单域名阻断",
			input:    "https://evil.com/callback",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, client.HasRedirectURI(tc.input))
		})
	}
}

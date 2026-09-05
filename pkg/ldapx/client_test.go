package ldapx

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveUserFilter(t *testing.T) {
	testCases := []struct {
		name         string
		filter       string
		username     string
		usernameAttr string
		mailAttr     string
		want         string
	}{
		{
			name:         "替换 input 占位符",
			filter:       "(&(objectClass=person)(sAMAccountName={input}))",
			username:     "alice",
			usernameAttr: "sAMAccountName",
			mailAttr:     "mail",
			want:         "(&(objectClass=person)(sAMAccountName=alice))",
		},
		{
			name:         "转义特殊字符防 LDAP 注入",
			filter:       "(&(objectClass=person)(uid={input}))",
			username:     "admin*)(uid=*))(|(uid=*",
			usernameAttr: "uid",
			mailAttr:     "mail",
			want:         `(&(objectClass=person)(uid=admin\2a\29\28uid=\2a\29\29\28|\28uid=\2a))`,
		},
		{
			name:         "多属性占位符替换",
			filter:       "(|({username_attribute}={input})({mail_attribute}={input}))",
			username:     "bob@example.com",
			usernameAttr: "mail",
			mailAttr:     "mail",
			want:         "(|(mail=bob@example.com)(mail=bob@example.com))",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveUserFilter(tc.filter, tc.username, tc.usernameAttr, tc.mailAttr)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestClient_Authenticate_EmptyPassword(t *testing.T) {
	c := NewClient(Config{})
	_, err := c.Authenticate(context.Background(), "(cn=alice)", "", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "密码不能为空")
}

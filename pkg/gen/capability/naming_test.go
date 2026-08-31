package capability

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNamingUtils(t *testing.T) {
	testCases := []struct {
		name       string
		input      string
		wantPascal string
		wantSnake  string
	}{
		{
			name:       "标准下划线转换",
			input:      "view_role_members",
			wantPascal: "ViewRoleMembers",
			wantSnake:  "view_role_members",
		},
		{
			name:       "带有中划线和点号转换",
			input:      "user.ldap-sync",
			wantPascal: "UserLdapSync",
			wantSnake:  "user.ldap-sync",
		},
		{
			name:       "大驼峰转蛇形",
			input:      "RoleTarget",
			wantPascal: "RoleTarget",
			wantSnake:  "role_target",
		},
		{
			name:       "单词转换",
			input:      "user",
			wantPascal: "User",
			wantSnake:  "user",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantPascal, ToPascalCase(tc.input))
			if tc.input == tc.wantPascal {
				assert.Equal(t, tc.wantSnake, ToSnakeCase(tc.input))
			}
		})
	}
}

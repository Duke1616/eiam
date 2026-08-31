package capability

import "strings"

// ToPascalCase 将蛇形或下划线命名转换为大驼峰标识符 (如 "view_role_members" -> "ViewRoleMembers")
func ToPascalCase(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	})

	var sb strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		sb.WriteString(strings.ToUpper(p[:1]) + p[1:])
	}
	return sb.String()
}

// ToSnakeCase 将大驼峰标识符转换为下划线蛇形 (如 "RoleMember" -> "role_member")
func ToSnakeCase(s string) string {
	var res []rune
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				res = append(res, '_')
			}
			res = append(res, r+('a'-'A'))
		} else {
			res = append(res, r)
		}
	}
	return string(res)
}

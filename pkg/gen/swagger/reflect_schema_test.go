package swagger

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

type SampleRoleReq struct {
	Name        string   `json:"name" binding:"required"`
	Code        string   `json:"code" binding:"required"`
	RoleIDs     []int64  `json:"role_ids"`
	Usernames   []string `json:"usernames"`
	Enabled     bool     `json:"enabled"`
	Limit       int      `json:"limit"`
	Description string   `json:"desc"`
}

func TestReflectSchemaEngine(t *testing.T) {
	engine := NewReflectSchemaEngine()
	schema := engine.Generate(SampleRoleReq{})

	assert.Equal(t, "object", schema.Type)
	assert.Contains(t, schema.Required, "name")
	assert.Contains(t, schema.Required, "code")

	// 检查属性推导
	assert.Equal(t, "string", schema.Properties["name"].Type)
	assert.Equal(t, "array", schema.Properties["role_ids"].Type)
	assert.Equal(t, "integer", schema.Properties["role_ids"].Items.Type)
	assert.Equal(t, "boolean", schema.Properties["enabled"].Type)
	assert.Equal(t, "integer", schema.Properties["limit"].Type)

	// 检查智能 Example 推导
	exampleMap, ok := schema.Example.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "示例名称", exampleMap["name"])
	assert.Equal(t, "admin", exampleMap["code"])
	assert.Equal(t, []int{1, 2, 3}, exampleMap["role_ids"])
	assert.Equal(t, []string{"admin", "guest"}, exampleMap["usernames"])
	assert.Equal(t, true, exampleMap["enabled"])
	assert.Equal(t, 10, exampleMap["limit"])
	assert.Equal(t, "相关业务描述信息", exampleMap["desc"])

	// 验证 reflect.Type 传参也一致
	schemaFromType := engine.Generate(reflect.TypeOf(SampleRoleReq{}))
	assert.Equal(t, schema, schemaFromType)
}

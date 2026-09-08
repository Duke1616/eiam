package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCasXML_Output(t *testing.T) {
	resp := NewCasSuccessResponse("admin", map[string]any{
		"email":       "admin@example.com",
		"name":        "系统管理员",
		"displayName": "系统管理员",
		"phone":       "13800138000",
		"title":       "架构师",
		"tenant_id":   int64(1),
		"id":          int64(1001),
	})
	output, err := resp.ToXML()
	require.NoError(t, err)
	assert.Contains(t, output, "<cas:user>admin</cas:user>")
	assert.Contains(t, output, "<cas:email>admin@example.com</cas:email>")
	assert.Contains(t, output, "<cas:name>系统管理员</cas:name>")
}


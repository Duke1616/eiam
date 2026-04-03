package urn

import (
	"fmt"
	"strings"
)

// URN 代表 eIAM 统一资源名
// 格式: eiam:{tenant}:{service}:{resource_type}/{resource_id}
// 示例: eiam:tenant_01:iam:api/user/list
type URN struct {
	Partition    string // 固定为 eiam
	TenantID     string // 租户标识
	Service      string // 服务名 (iam, cmdb, etc.)
	ResourceType string // 资源类型 (api, menu, role)
	ResourceID   string // 资源路径或具体 ID
}

func (u URN) String() string {
	return fmt.Sprintf("%s:%s:%s:%s/%s",
		u.Partition, u.TenantID, u.Service, u.ResourceType, u.ResourceID)
}

// New 生成一个新的 URN
func New(tenant, service, resType, resID string) URN {
	return URN{
		Partition:    "eiam",
		TenantID:     tenant,
		Service:      service,
		ResourceType: resType,
		ResourceID:   resID,
	}
}

// Match 简单的通配符匹配逻辑 (以后可扩展为更复杂的匹配)
func Match(pattern, target string) bool {
	if pattern == "*" {
		return true
	}
	// 将 pattern 中的 * 替换为正则或简单的后缀匹配
	// 为了演示，这里实现最基础的全匹配
	return pattern == target || strings.HasPrefix(target, strings.TrimSuffix(pattern, "*"))
}

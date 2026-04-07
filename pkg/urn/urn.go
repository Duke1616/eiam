package urn

import (
	"fmt"
	"strings"
)

// URN 代表 eIAM 统一资源名
// 格式: eiam:{tenant}:{service}:{resource_type}:{resource_id}
// 示例: eiam:0:iam:menu:user/list
type URN struct {
	Partition    string // 固定为 eiam
	TenantID     string // 租户标识 (系统全局资产固定为 "0")
	Service      string // 服务名 (iam, cmdb, etc.)
	ResourceType string // 资源类型 (api, menu, role)
	ResourceID   string // 资源路径或具体 ID (支持 * 通配符)
}

func (u URN) String() string {
	return fmt.Sprintf("%s:%s:%s:%s:%s",
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

// Match 高性能通配符匹配逻辑 (仿路径匹配)
func Match(pattern, target string) bool {
	if pattern == "*" || pattern == target {
		return true
	}

	// 将 pattern 中的通配符转换为可匹配逻辑
	// 这里简单实现：支持 * 匹配任意内容
	// 如果需要精准路径匹配，建议在此集成正则或专门的路由匹配器
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == target
	}

	if !strings.HasPrefix(target, parts[0]) {
		return false
	}

	for i := 1; i < len(parts); i++ {
		if parts[i] == "" { // 尾部通配符
			return true
		}
		// 检查后续部分是否存在
		idx := strings.Index(target, parts[i])
		if idx == -1 {
			return false
		}
		target = target[idx+len(parts[i]):]
	}

	return len(target) == 0 || pattern[len(pattern)-1] == '*'
}

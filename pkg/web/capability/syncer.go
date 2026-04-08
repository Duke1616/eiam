package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// SyncRequest 定义了 SDK 上报资产给 EIAM 的标准协议
type SyncRequest struct {
	Service     string         `json:"service"`     // 服务标识，如 "order-service"
	Permissions []Permission   `json:"permissions"` // 逻辑权限全集
	APIs        []ResourceInfo `json:"apis"`        // 物理 API 资产全集
}

// PermSyncer 资产同步 SDK 的核心交互接口。
// 使用者应通过 NewPermSyncer 工厂函数进行初始化。
type PermSyncer interface {
	// SyncAuto 全自动同步：资产发现 (Collector) -> 协议封装 (SyncRequest) -> 远程同步 (Sync)
	SyncAuto(ctx context.Context, providers []PermissionProvider, router *gin.Engine) error

	// Sync 手动同步：将已有的资产请求对象同步至远程 EIAM 决策中心
	Sync(ctx context.Context, req SyncRequest) error
}

// defaultPermSyncer EIAM SDK 的默认同步器实现
type defaultPermSyncer struct {
	service  string
	endpoint string
	client   *http.Client
}

// NewPermSyncer 构建一个标准权限同步 SDK 实例
// service: 当前服务的唯一标识 (URN 前缀)
// endpoint: EIAM 中心化发现 API 的完整路径
func NewPermSyncer(service, endpoint string) PermSyncer {
	return &defaultPermSyncer{
		service:  service,
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SyncAuto 实现全自动化的“扫描-上报”闭环
func (s *defaultPermSyncer) SyncAuto(ctx context.Context, providers []PermissionProvider, router *gin.Engine) error {
	// 1. 资产发现：利用 Collector 扫描所有注册的 Provider 与路由装饰器
	collector := NewCollector(router).RegisterProviders(providers...)
	perms, apis := collector.Collect()

	// 2. 协议封装与远程同步
	return s.Sync(ctx, SyncRequest{
		Service:     s.service,
		Permissions: perms,
		APIs:        apis,
	})
}

// Sync 实现基础的底层同步逻辑
func (s *defaultPermSyncer) Sync(ctx context.Context, req SyncRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("EIAM SDK 协议序列化失败: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", s.endpoint, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("EIAM SDK 构建请求失败: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("EIAM SDK 网络请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("EIAM 服务返回异常状态码: %d", resp.StatusCode)
	}

	return nil
}

package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SyncRequest 定义了 SDK 上报资产给 EIAM 的标准协议
type SyncRequest struct {
	Service     string         `json:"service"`     // 服务标识，如 "order-service"
	Permissions []Permission   `json:"permissions"` // 逻辑权限全集
	APIs        []ResourceInfo `json:"apis"`        // 物理 API 资产全集
}

// Syncer 定义同步逻辑接口
type Syncer interface {
	Sync(ctx context.Context, req SyncRequest) error
}

// HTTPClient EIAM SDK 的默认同步实现
type HTTPClient struct {
	Endpoint string
	client   *http.Client
}

func NewHTTPClient(endpoint string) *HTTPClient {
	return &HTTPClient{
		Endpoint: endpoint,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (h *HTTPClient) Sync(ctx context.Context, req SyncRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", h.Endpoint, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("EIAM 同步失败，HTTP 状态码: %d", resp.StatusCode)
	}

	return nil
}

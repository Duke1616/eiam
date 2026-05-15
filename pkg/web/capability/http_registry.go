package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type httpRegistry struct {
	endpoint string
	client   *http.Client
}

// NewHttpRegistry 构建一个基于 HTTP POST 的同步器
func NewHttpRegistry(endpoint string) Registry {
	return &httpRegistry{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (r *httpRegistry) Sync(ctx context.Context, req SyncRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("EIAM SDK 协议序列化失败: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", r.endpoint, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("EIAM SDK 构建请求失败: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("EIAM SDK 网络请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("EIAM 服务返回异常状态码: %d", resp.StatusCode)
	}

	return nil
}

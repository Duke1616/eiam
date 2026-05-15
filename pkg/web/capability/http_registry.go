package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gotomicro/ego/core/elog"
	"github.com/spf13/viper"
)

type httpRegistry struct {
	endpoint string
	client   *http.Client
	l        *elog.Component

	// 简化为单个服务的注册控制器
	mu   sync.RWMutex
	req  SyncRequest
	once sync.Once
}

// NewHttpRegistry 从 viper 配置中自动读取地址并构建注册器
func NewHttpRegistry() Registry {
	url := viper.GetString("policy.discovery_url")
	if url == "" {
		// 如果未配置，默认走本地或者报错
		url = "http://127.0.0.1:8000"
	}
	return NewHttpRegistryWithURL(url)
}

// NewHttpRegistryWithURL 显式传入地址构建注册器
func NewHttpRegistryWithURL(endpoint string) Registry {
	endpoint = strings.TrimRight(endpoint, "/")
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "http://" + endpoint
	}
	// 自动补齐 API 路径
	if !strings.Contains(endpoint, "/api/v1/discovery/sync") {
		endpoint = endpoint + "/api/v1/discovery/sync"
	}

	return &httpRegistry{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		l: elog.DefaultLogger.With(elog.FieldComponentName("discovery-sdk")),
	}
}

func (r *httpRegistry) Sync(ctx context.Context, req SyncRequest) error {
	// 1. 更新当前要同步的数据
	r.mu.Lock()
	r.req = req
	r.mu.Unlock()

	// 2. 确保心跳协程只启动一次
	r.once.Do(func() {
		go r.runRegistrationLoop()
	})

	return nil
}

func (r *httpRegistry) runRegistrationLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// 这里的 Context 使用 Background，因为它是长驻任务
	ctx := context.Background()

	for {
		// 获取最新快照
		r.mu.RLock()
		req := r.req
		r.mu.RUnlock()

		if err := r.doPost(ctx, req); err != nil {
			r.l.Error("EIAM SDK HTTP 资产报备异常",
				elog.String("service", req.Service),
				elog.FieldErr(err))
		}

		<-ticker.C
	}
}

func (r *httpRegistry) doPost(ctx context.Context, req SyncRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", r.endpoint, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("EIAM 服务返回异常状态码: %d", resp.StatusCode)
	}

	return nil
}

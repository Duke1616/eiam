package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/gotomicro/ego/core/elog"
	"github.com/spf13/viper"
)

type httpReporter struct {
	endpoint string
	client   *http.Client
	l        *elog.Component

	mu   sync.RWMutex
	req  capability.SyncRequest
	once sync.Once
}

// New 从 viper 配置中自动读取 policy.discovery_url 构建 HTTP 上报器
func New() capability.Reporter {
	url := viper.GetString("policy.discovery_url")
	if url == "" {
		url = "http://127.0.0.1:8000"
	}
	return NewWithURL(url)
}

// NewWithURL 显式传入地址构建 HTTP 上报器
func NewWithURL(endpoint string) capability.Reporter {
	endpoint = strings.TrimRight(endpoint, "/")
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "http://" + endpoint
	}
	if !strings.Contains(endpoint, "/api/v1/discovery/sync") {
		endpoint = endpoint + "/api/v1/discovery/sync"
	}

	return &httpReporter{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 10 * time.Second},
		l:        elog.DefaultLogger,
	}
}

func (r *httpReporter) Sync(ctx context.Context, req capability.SyncRequest) error {
	r.mu.Lock()
	r.req = req
	r.mu.Unlock()

	// 初次上报立即执行一次同步
	if err := r.doReport(ctx, req); err != nil {
		r.l.Warn("首次资产上报失败，后台轮询将继续重试", elog.FieldErr(err))
	}

	// 启动后台定时心跳上报
	r.once.Do(func() {
		go r.startReportingLoop()
	})

	return nil
}

func (r *httpReporter) startReportingLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		r.mu.RLock()
		req := r.req
		r.mu.RUnlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := r.doReport(ctx, req); err != nil {
			r.l.Warn("定时同步资产失败", elog.FieldErr(err), elog.String("endpoint", r.endpoint))
		}
		cancel()
	}
}

func (r *httpReporter) doReport(ctx context.Context, req capability.SyncRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("序列化资产上报请求失败: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("构建资产上报 HTTP 请求失败: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("发送资产上报请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("资产上报端点返回非正常状态码: %d", resp.StatusCode)
	}

	return nil
}

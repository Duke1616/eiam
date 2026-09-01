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
	secret   string
	client   *http.Client
	l        *elog.Component

	mu               sync.RWMutex
	req              capability.SyncRequest
	lastReportedHash string
	once             sync.Once
}

// Option 定义 httpReporter 的可选配置函数
type Option func(*httpReporter)

// WithSecret 设置访问 EIAM 服务端所需的通信密钥 (Bearer Secret)
func WithSecret(secret string) Option {
	return func(r *httpReporter) {
		r.secret = secret
	}
}

// WithClient 自定义 HTTP Client
func WithClient(client *http.Client) Option {
	return func(r *httpReporter) {
		if client != nil {
			r.client = client
		}
	}
}

// New 从 viper 配置中自动读取 policy.discovery_url 与 policy.discovery_token 构建 HTTP 上报器
func New(opts ...Option) capability.Reporter {
	url := viper.GetString("policy.discovery_url")
	if url == "" {
		url = "http://127.0.0.1:8000"
	}

	token := viper.GetString("policy.discovery_token")

	defaultOpts := []Option{}
	if token != "" {
		defaultOpts = append(defaultOpts, WithSecret(token))
	}
	defaultOpts = append(defaultOpts, opts...)

	return NewWithURL(url, defaultOpts...)
}

// NewWithURL 显式传入地址构建 HTTP 上报器
func NewWithURL(endpoint string, opts ...Option) capability.Reporter {
	endpoint = strings.TrimRight(endpoint, "/")
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "http://" + endpoint
	}
	if !strings.Contains(endpoint, "/api/v1/discovery/sync") {
		endpoint = endpoint + "/api/v1/discovery/sync"
	}

	r := &httpReporter{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 10 * time.Second},
		l:        elog.DefaultLogger.With(elog.FieldComponent("capability-http-reporter")),
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
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
	currentHash := req.Hash()

	r.mu.RLock()
	lastHash := r.lastReportedHash
	r.mu.RUnlock()

	// 性能短路优化：如果资产 Hash 没有发生改变，跳过 HTTP 发送，零网络开销
	if lastHash != "" && lastHash == currentHash {
		return nil
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("序列化资产上报请求失败: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("构建资产上报 HTTP 请求失败: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// 若配置了 Secret，自动注入业界标准 Bearer 凭据头
	if r.secret != "" {
		httpReq.Header.Set("Authorization", "Bearer "+r.secret)
	}

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("发送资产上报请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("资产上报端点返回非正常状态码: %d", resp.StatusCode)
	}

	// 上报成功后更新本地缓存的最新已上报 Hash
	r.mu.Lock()
	r.lastReportedHash = currentHash
	r.mu.Unlock()

	return nil
}

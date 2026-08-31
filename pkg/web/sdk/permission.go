package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
	"github.com/samber/lo"
	"github.com/spf13/viper"
)

// Option 配置 SDK 的可选函数式选项
type Option func(*SDK)

// WithTimeout 自定义远程鉴权超时时间
func WithTimeout(timeout time.Duration) Option {
	return func(s *SDK) {
		s.client.Timeout = timeout
	}
}

// WithClient 自定义 HTTP 客户端
func WithClient(client *http.Client) Option {
	return func(s *SDK) {
		if client != nil {
			s.client = client
		}
	}
}

// SDK 提供登录验证和权限鉴权的 Gin 中间件
type SDK struct {
	baseURL    string
	client     *http.Client
	logger     *elog.Component
	pathPrefix string
}

// NewSDK 创建鉴权 SDK 实例 (服务名将通过 capability 自动感知识别)
func NewSDK(opts ...Option) *SDK {
	baseURL := viper.GetString("policy.auth_url")
	if baseURL == "" {
		panic("policy.auth_url 未配置，请在配置文件中声明 policy.auth_url")
	}
	return NewSDKWithURL(baseURL, opts...)
}

// NewSDKWithURL 创建鉴权 SDK 实例，显式传入地址
func NewSDKWithURL(baseURL string, opts ...Option) *SDK {
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8000"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}

	// 针对鉴权高并发调用场景调优的专用 Transport 连接池
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100, // 显著突破标准库默认 2 的瓶颈
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	sdk := &SDK{
		baseURL: baseURL,
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second, // 避免服务端卡死引发下游协程泄漏
		},
		logger: elog.DefaultLogger.With(elog.FieldComponentName("policy-sdk")),
	}

	for _, opt := range opts {
		opt(sdk)
	}

	return sdk
}

func (s *SDK) WithPathPrefix(prefix string) *SDK {
	s.pathPrefix = normalizePathPrefix(prefix)
	return s
}

type checkLoginResp struct {
	Uid      json.Number `json:"uid"`
	TenantID json.Number `json:"tenant_id"`
}

type checkPolicyReq struct {
	Service  string `json:"service"`  // 物理维度：定位哪个服务的 API
	Path     string `json:"path"`     // 物理维度
	Method   string `json:"method"`   // 物理维度
	Resource string `json:"resource"` // 逻辑维度：判定哪个资源实例，如 "*" 或 "project:1"
}

type authorizeResult = pbac.Decision

type apiResult[T any] struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data T      `json:"data"`
}

// CheckLogin 登录检查中间件
func (s *SDK) CheckLogin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var res apiResult[checkLoginResp]
		if err := s.callAPI(ctx, "/api/permission/check_login", nil, &res); err != nil {
			s.logger.Error("CheckLogin 远程鉴权失败", elog.FieldErr(err))
			return
		}

		uid, err := res.Data.Uid.Int64()
		if err != nil || uid <= 0 {
			s.logger.Error("CheckLogin 用户ID解析异常", elog.FieldErr(err), elog.Any("data", res.Data))
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, ginx.Result{Code: 401001, Msg: "登录凭据无效"})
			return
		}

		tid, err := res.Data.TenantID.Int64()
		if err != nil || tid <= 0 {
			s.logger.Error("CheckLogin 租户ID解析异常", elog.FieldErr(err), elog.Any("data", res.Data))
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, ginx.Result{Code: 401002, Msg: "租户身份凭据无效"})
			return
		}

		// 注入 context.WithValue (仅单通道，SDK 下游服务同样开启 ContextWithFallback)
		// tenant_id = 执行租户 (数据隔离)，origin_tenant_id = 身份租户 (鉴权校验)
		ctx.Request = ctx.Request.WithContext(ctxutil.WithUserAndTenant(ctx.Request.Context(), uid, tid))

		ctx.Next()
	}
}

// CheckPolicy 权限鉴权中间件
// resource: 填写授权判断的业务资源标识 (逻辑维度)，如 "project:1"
// 如果不传或传空，中间件将尝试通过 capability SDK 自动识别 Service 和模板 Path 信息。
func (s *SDK) CheckPolicy() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ptr := reflect.ValueOf(ctx.Handler()).Pointer()
		info, ok := capability.GetResourceInfo(ptr)
		if !ok {
			// 未打标接口，默认仅需要登录校验 (由 session 中间件负责)，此处直接跳过鉴权
			ctx.Next()
			return
		}

		// 3. 发起远程判定
		path, method := s.resolvePolicyPath(ctx.FullPath()), ctx.Request.Method
		var res apiResult[authorizeResult]
		if err := s.callAPI(ctx, "/api/permission/check_policy", checkPolicyReq{
			Service: info.Service,
			Path:    path,
			Method:  method,
		}, &res); err != nil {
			return
		}

		if !res.Data.Allowed {
			reason := lo.CoalesceOrEmpty(res.Data.Reason, "没有权限执行该操作")
			s.logger.Warn("鉴权拒绝",
				elog.String("service", info.Service),
				elog.String("method", method),
				elog.String("path", path),
				elog.String("reason", reason))
			ctx.AbortWithStatusJSON(http.StatusForbidden, ginx.Result{
				Code: 403001,
				Msg:  reason,
			})
			return
		}
		if res.Data.FilterProfile != info.FilterProfile {
			s.logger.Warn("数据过滤画像不匹配拒绝",
				elog.String("expected", string(info.FilterProfile)),
				elog.String("actual", string(res.Data.FilterProfile)))
			ctx.AbortWithStatusJSON(http.StatusForbidden, ginx.Result{
				Code: 403002,
				Msg:  "数据范围约束配置不匹配",
			})
			return
		}

		ctx.Request = ctx.Request.WithContext(pbac.WithDecision(ctx.Request.Context(), res.Data))
		ctx.Next()
	}
}

func (s *SDK) resolvePolicyPath(path string) string {
	path = lo.CoalesceOrEmpty(strings.TrimSpace(path), "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if s.pathPrefix == "" {
		return path
	}
	return lo.Ternary(path == "/", s.pathPrefix, s.pathPrefix+path)
}

func normalizePathPrefix(prefix string) string {
	trimmed := strings.Trim(strings.TrimSpace(prefix), "/")
	return lo.Ternary(trimmed == "", "", "/"+trimmed)
}

// callAPI 内部处理透传和请求发送
func (s *SDK) callAPI(ctx *gin.Context, path string, body any, out any) error {
	// 1. 当 body 为空时使用 http.NoBody 避免堆内存分配
	var bodyReader io.Reader = http.NoBody
	if body != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
		bodyReader = &buf
	}

	req, err := http.NewRequestWithContext(ctx.Request.Context(), "POST", s.baseURL+path, bodyReader)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return err
	}

	// 2. 精准透传鉴定身份所需的关键 Header，不再全量 Clone (性能优化)
	req.Header.Set("Content-Type", "application/json")
	if auth := ctx.GetHeader("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if sess := ctx.GetHeader("Cookie"); sess != "" {
		req.Header.Set("Cookie", sess)
	}
	if reqID := ctx.GetHeader("X-Request-Id"); reqID != "" {
		req.Header.Set("X-Request-Id", reqID)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Error("远程鉴权请求发送失败", elog.FieldErr(err))
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return err
	}
	defer resp.Body.Close()

	// 3. 精准回传凭证与状态 (若鉴权中心续期或变更了 Cookie，回传给客户端)
	if setCookie := resp.Header.Get("Set-Cookie"); setCookie != "" {
		ctx.Header("Set-Cookie", setCookie)
	}

	if resp.StatusCode != http.StatusOK {
		ctx.AbortWithStatus(resp.StatusCode)
		return fmt.Errorf("鉴权中心状态异常: %d", resp.StatusCode)
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/Duke1616/eiam/pkg/utils/batcher"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
	"github.com/samber/lo"
	"github.com/spf13/viper"
)

var (
	// forwardHeaders 定义需要向下透传的 HTTP 标头白名单
	forwardHeaders = []string{"Authorization", "Cookie", "X-Request-Id"}

	// bufferPool 复用 JSON 序列化 Buffer，高并发鉴权下避免频繁堆分配与 GC 压力
	bufferPool = sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}
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

// SDK 提供登录验证、权限鉴权与内生合规审计的统一集成 SDK
type SDK struct {
	baseURL    string
	client     *http.Client
	logger     *elog.Component
	pathPrefix string
	batcher    *batcher.Batcher[OperationRecord]
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
	baseURL = lo.CoalesceOrEmpty(baseURL, "http://127.0.0.1:8000")
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

	// 启动企业级内生合规审计批处理引擎 (Fail-Safe 丢弃保护，业务执行 0ms 延迟损耗)
	sdk.batcher = batcher.NewBatcher(
		sdk.flushAuditBatch,
		batcher.WithBatchSize[OperationRecord](50),
		batcher.WithBufferCap[OperationRecord](2000),
		batcher.WithFlushInterval[OperationRecord](500*time.Millisecond),
	)

	return sdk
}

// Close 优雅停止 SDK 并在进程退出前尽力刷出积压审计日志
func (s *SDK) Close() {
	if s.batcher != nil {
		s.batcher.Close()
	}
}

// flushAuditBatch 后台单协程批量聚合投递至 EIAM 服务端接收端点
func (s *SDK) flushAuditBatch(ctx context.Context, batch []OperationRecord) error {
	var res apiResult[any]
	return s.callAPIWithCtx(ctx, "/api/audit/batch", map[string]any{"records": batch}, &res)
}

func (s *SDK) WithPathPrefix(prefix string) *SDK {
	s.pathPrefix = normalizePathPrefix(prefix)
	return s
}

type checkLoginResp struct {
	Uid      json.Number `json:"uid"`
	TenantID json.Number `json:"tenant_id"`
	Username string      `json:"username"`
}

type checkPolicyReq struct {
	Service  string `json:"service"`  // 物理维度：定位哪个服务的 API
	Path     string `json:"path"`     // 物理维度
	Method   string `json:"method"`   // 物理维度
	Resource string `json:"resource"` // 逻辑维度：判定哪个资源实例，如 "*" 或 "project:1"
}

type authorizeResult struct {
	pbac.Decision
	Audit bool `json:"audit"`
}

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

		// 注入 context.WithValue (包含用户ID、租户ID与用户名，供下游服务与内生审计透传使用)
		ctx.Request = ctx.Request.WithContext(ctxutil.WithUserInfo(ctx.Request.Context(), uid, tid, res.Data.Username))

		ctx.Next()
	}
}

// CheckPolicy 权限鉴权与内生合规审计集成切面 (微服务接入 EIAM 的核心枢纽)
// 1. 强力保证：只要接入 EIAM，写操作强制被合规审计，业务微服务无需任何配置
// 2. 极致性能：业务执行完毕推入本地无锁环形队列 (< 50ns)，响应延迟增加 0ms
// 3. 容灾隔离：审计队列满或网络波动时执行 Fail-Safe 丢弃保护，绝对不阻断业务接口返回
func (s *SDK) CheckPolicy() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ptr := reflect.ValueOf(ctx.Handler()).Pointer()
		info, ok := capability.GetResourceInfo(ptr)
		if !ok {
			// 未打标接口，默认仅需要登录校验 (由 session 中间件负责)，此处直接跳过鉴权
			ctx.Next()
			return
		}

		// 1. 发起远程统一鉴权判定
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

		ctx.Request = ctx.Request.WithContext(pbac.WithDecision(ctx.Request.Context(), res.Data.Decision))

		// 2. 根据 EIAM 集中下发的决策指令判断是否需要审计 (EIAM 统一配置管控，微服务零配置即时生效)
		if !res.Data.Audit {
			ctx.Next()
			return
		}

		// 3. 环绕切面放行执行业务 Handler
		startTime := time.Now()
		ctx.Next()

		// 4. 透明采集业务执行状态并极速入队
		var err error
		if len(ctx.Errors) > 0 {
			err = ctx.Errors.Last()
		}
		status, failReason := capability.EvaluateHTTPStatus(ctx.Writer.Status(), err)

		reqCtx := ctx.Request.Context()
		record := OperationRecord{
			TenantID:     ctxutil.GetTenantID(reqCtx).Int64(),
			Service:      info.Service,
			OperatorID:   ctxutil.GetUserID(reqCtx).Int64(),
			OperatorName: ctxutil.GetUsername(reqCtx),
			Module:       info.Group,
			Action:       info.Code,
			ResourceID:   extractParam(ctx),
			ResourceName: info.Name,
			ResourceURN:  capability.BuildApiURN(info.Service, method, path),
			AfterState:   ctx.Request.URL.RawQuery,
			Status:       status,
			FailReason:   failReason,
			ClientIP:     ctx.ClientIP(),
			UserAgent:    ctx.Request.UserAgent(),
			Ctime:        startTime.UnixMilli(),
		}

		// 非阻塞投递至批处理器
		_ = s.batcher.Push(record)
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
	headers := make(http.Header, len(forwardHeaders))
	for _, key := range forwardHeaders {
		if val := ctx.GetHeader(key); val != "" {
			headers.Set(key, val)
		}
	}

	setCookie, err := s.doRequest(ctx.Request.Context(), path, body, headers, out)
	if setCookie != "" {
		ctx.Header("Set-Cookie", setCookie)
	}
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return err
	}
	return nil
}

func (s *SDK) callAPIWithCtx(ctx context.Context, path string, body any, out any) error {
	_, err := s.doRequest(ctx, path, body, nil, out)
	return err
}

func (s *SDK) doRequest(ctx context.Context, path string, body any, headers http.Header, out any) (string, error) {
	var bodyReader io.Reader = http.NoBody
	if body != nil {
		buf := bufferPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufferPool.Put(buf)

		if err := json.NewEncoder(buf).Encode(body); err != nil {
			return "", err
		}
		bodyReader = buf
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.baseURL+path, bodyReader)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header[k] = v
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Error("请求鉴权中心服务失败", elog.FieldErr(err), elog.String("path", path))
		return "", err
	}
	defer resp.Body.Close()

	setCookie := resp.Header.Get("Set-Cookie")
	if resp.StatusCode != http.StatusOK {
		return setCookie, fmt.Errorf("鉴权中心状态异常: %d", resp.StatusCode)
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return setCookie, err
		}
	}
	return setCookie, nil
}

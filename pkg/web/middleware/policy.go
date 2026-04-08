package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
	"github.com/spf13/viper"
)

// SDK 提供登录验证和权限鉴权的 Gin 中间件
type SDK struct {
	baseURL string
	client  *http.Client
	logger  *elog.Component
}

// NewSDK 创建鉴权 SDK 实例 (服务名将通过 capability 自动感知识别)
func NewSDK() *SDK {
	baseURL := viper.GetString("policy.auth_url")
	if baseURL == "" {
		panic("policy.auth_url 未配置，请在配置文件中声明 policy.auth_url")
	}
	return NewSDKWithURL(baseURL)
}

// NewSDKWithURL 创建鉴权 SDK 实例，显式传入地址
func NewSDKWithURL(baseURL string) *SDK {
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8000"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	return &SDK{
		baseURL: baseURL,
		client:  &http.Client{},
		logger:  elog.DefaultLogger.With(elog.FieldComponentName("policy-sdk")),
	}
}

type checkLoginResp struct {
	Uid int64 `json:"uid"`
}

type checkPolicyReq struct {
	Service  string `json:"service"`  // 物理维度：定位哪个服务的 API
	Path     string `json:"path"`     // 物理维度
	Method   string `json:"method"`   // 物理维度
	Resource string `json:"resource"` // 逻辑维度：判定哪个资源实例，如 "*" 或 "project:1"
}

type authorizeResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
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
		if err := s.callAPI(ctx, "/api/policy/check_login", nil, &res); err != nil {
			return
		}

		ctx.Set("uid", res.Data.Uid)
		ctx.Next()
	}
}

// CheckPolicy 权限鉴权中间件
// resource: 填写授权判断的业务资源标识 (逻辑维度)，如 "project:1"
// 如果不传或传空，中间件将尝试通过 capability SDK 自动识别 Service 和模板 Path 信息。
func (s *SDK) CheckPolicy(resource string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 1. 获取物理元数据：优先通过 Handler 指针反查
		ptr := reflect.ValueOf(ctx.Handler()).Pointer()
		info, ok := capability.GetResourceInfo(ptr)
		if !ok {
			// 未打标接口，默认仅需要登录校验 (由 session 中间件负责)，此处直接跳过鉴权
			ctx.Next()
			return
		}

		// 2. 提取自动识别的服务名和模板路径 (解决 /user/:id 这种动态参数问题)
		service := info.Service
		path := info.Path

		// 3. 环境聚合
		if resource == "" {
			resource = "*"
		}

		// 4. 发起远程判定
		var res apiResult[authorizeResult]
		if err := s.callAPI(ctx, "/api/policy/check_policy", checkPolicyReq{
			Service:  service,
			Path:     path,
			Method:   ctx.Request.Method,
			Resource: resource,
		}, &res); err != nil {
			return
		}

		if !res.Data.Allowed {
			s.logger.Warn("鉴权拒绝",
				elog.String("service", service),
				elog.String("path", path),
				elog.String("resource", resource),
				elog.String("reason", res.Data.Reason))
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}

		ctx.Next()
	}
}

// callAPI 内部处理透传和请求发送
func (s *SDK) callAPI(ctx *gin.Context, path string, body any, out any) error {
	// 1. 使用 Buffer 或 Encoder 减少内存映射次数
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}

	req, err := http.NewRequestWithContext(ctx.Request.Context(), "POST", s.baseURL+path, &buf)
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

	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Error("远程鉴权请求发送失败", elog.FieldErr(err))
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return err
	}
	defer resp.Body.Close()

	// 3. 精准回传所需的业务 Header (安全性优化)
	// 中心化鉴权通常只涉及 Token 的下发与续期
	if token := resp.Header.Get("x-jwt-token"); token != "" {
		ctx.Header("x-jwt-token", token)
	}

	if resp.StatusCode != http.StatusOK {
		ctx.AbortWithStatus(resp.StatusCode)
		return fmt.Errorf("鉴权中心状态异常: %d", resp.StatusCode)
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

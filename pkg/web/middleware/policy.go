package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gotomicro/ego/core/elog"
	"github.com/spf13/viper"
)

// SDK 提供登录验证和权限鉴权的 Gin 中间件
type SDK struct {
	service string // 当前业务服务名：如 "iam", "cmdb"
	baseURL string
	client  *http.Client
	logger  *elog.Component
}

// NewSDK 创建鉴权 SDK 实例
// service: 当前服务的唯一标识
func NewSDK(service string) *SDK {
	baseURL := viper.GetString("policy.auth_url")
	if baseURL == "" {
		panic("policy.auth_url 未配置，请在配置文件中声明 policy.auth_url")
	}
	return NewSDKWithURL(service, baseURL)
}

// NewSDKWithURL 创建鉴权 SDK 实例，显式传入地址和服务的服务名
func NewSDKWithURL(service string, baseURL string) *SDK {
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8000"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	return &SDK{
		service: service,
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
// resource: 填写该接口操作的业务资源标识，默认为 "*" 
func (s *SDK) CheckPolicy(resource string) gin.HandlerFunc {
	if resource == "" {
		resource = "*"
	}
	return func(ctx *gin.Context) {
		var res apiResult[authorizeResult]
		if err := s.callAPI(ctx, "/api/policy/check_policy", checkPolicyReq{
			Service:  s.service,
			Path:     ctx.Request.URL.Path,
			Method:   ctx.Request.Method,
			Resource: resource,
		}, &res); err != nil {
			return
		}

		if !res.Data.Allowed {
			s.logger.Warn("鉴权拒绝",
				elog.String("service", s.service),
				elog.String("path", ctx.Request.URL.Path),
				elog.String("resource", resource),
				elog.String("reason", res.Data.Reason))
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}

		ctx.Next()
	}
}

// callAPI 保持原样，内部处理透传和请求发送...
func (s *SDK) callAPI(ctx *gin.Context, path string, body any, out any) error {
	var reqBody *bytes.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reqBody = bytes.NewReader(data)
	} else {
		reqBody = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx.Request.Context(), "POST", s.baseURL+path, reqBody)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return err
	}

	req.Header = ctx.Request.Header.Clone()
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		return err
	}
	defer resp.Body.Close()

	for k, vals := range resp.Header {
		if k == "Content-Length" || k == "Content-Type" {
			continue
		}
		for _, v := range vals {
			ctx.Writer.Header().Add(k, v)
		}
	}

	if resp.StatusCode != http.StatusOK {
		ctx.AbortWithStatus(resp.StatusCode)
		return fmt.Errorf("鉴权中心返回状态码: %d", resp.StatusCode)
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

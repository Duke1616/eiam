package capability

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

const (
	// StatusSuccess 操作或执行成功
	StatusSuccess = "SUCCESS"
	// StatusFailed 操作或执行失败
	StatusFailed = "FAIL"
)

// BuildApiURN 生成符合 EIAM 全局规范的 API 统一资源标识符
// 规范标准: urn:iam:api:<service>:<method>:<path>
func BuildApiURN(service, method, path string) string {
	svc := lo.CoalesceOrEmpty(strings.TrimSpace(service), "iam")
	m := strings.ToLower(strings.TrimSpace(method))
	p := strings.TrimSpace(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return "urn:iam:api:" + svc + ":" + m + ":" + p
}

// ExtractResourceParam 自动探测 Gin 路由参数中常见的资源唯一主键标识
func ExtractResourceParam(ctx *gin.Context) string {
	return lo.CoalesceOrEmpty(
		ctx.Param("id"),
		ctx.Param("uid"),
		ctx.Param("code"),
		ctx.Param("key"),
	)
}

// EvaluateHTTPStatus 依据 HTTP 状态码及 Gin Errors 评估最终执行状态与失败原因，
// 避免在高频接口中解析 Response Body 造成严重的序列化与 CPU 损耗
func EvaluateHTTPStatus(statusCode int, errors ...error) (status, failReason string) {
	hasErr := len(errors) > 0 && errors[0] != nil
	if statusCode >= http.StatusBadRequest || hasErr {
		status = StatusFailed
		if hasErr {
			failReason = errors[0].Error()
		} else {
			failReason = http.StatusText(statusCode)
		}
		return status, failReason
	}
	return StatusSuccess, ""
}

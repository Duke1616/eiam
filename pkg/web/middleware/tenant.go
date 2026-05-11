package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx"
	"github.com/ecodeclub/ginx/gctx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
)

// BuildTenancyContext 租户与用户信息上下文解析、安全校验及注入中间件
// 该中间件集成了：身份注入、多租户防篡权校验、租户上下文篡改三大功能
func BuildTenancyContext(sp session.Provider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// 1. 获取当前 Session 信息
		sess, err := sp.Get(&gctx.Context{Context: ctx})
		if err != nil {
			// 如果没有 Session（如公开接口），直接跳过
			ctx.Next()
			return
		}

		uid := sess.Claims().Uid
		currentTid, _ := strconv.ParseInt(sess.Claims().Data["tenant_id"], 10, 64)

		// 2. 探测请求中的目标租户 (target_tid)
		targetTid := extractTargetTid(ctx)

		// 3. 确定最终执行租户 (Final Tenant ID)
		finalTid := currentTid

		// 如果请求显式指定了目标租户，且与当前租户不符
		if targetTid != 0 && targetTid != currentTid {
			// 安全校验：只有系统级管理员允许跨租户操作
			// 特殊情况：如果当前请求在 Capability 中声明了 AllowCrossTenant (如切换租户)，则允许跨租户
			isExempt := false
			if handler := ctx.Handler(); handler != nil {
				ptr := reflect.ValueOf(handler).Pointer()
				if info, ok := capability.GetResourceInfo(ptr); ok && info.AllowCrossTenant {
					isExempt = true
				}
			}

			if currentTid != ctxutil.SystemTenantID && !isExempt {
				ctx.AbortWithStatusJSON(http.StatusForbidden, ginx.Result{
					Code: 403001,
					Msg:  "检测到跨租户越权操作，该请求已被安全拦截",
				})
				return
			}
			// 授权通过（超管或白名单接口）：使用目标租户 ID 注入上下文，确保 Service 层能正确穿透
			finalTid = targetTid
		}

		// 4. 注入上下文 (Web 层与标准 Context 同步)
		ctx.Set("uid", uid)
		ctx.Set("tenant_id", finalTid)
		ctx.Set("origin_tenant_id", currentTid)

		newCtx := ctxutil.WithUserID(ctx.Request.Context(), uid)
		newCtx = ctxutil.WithTenantID(newCtx, finalTid)
		newCtx = ctxutil.WithOriginTenantID(newCtx, currentTid)
		ctx.Request = ctx.Request.WithContext(newCtx)

		ctx.Next()
	}
}

// extractTargetTid 高效提取请求中的目标租户 ID
func extractTargetTid(ctx *gin.Context) int64 {
	// 1. 优先尝试从 URL Query 中提取 (性能开销极低)
	if tidStr := ctx.Query("tenant_id"); tidStr != "" {
		if tid, err := strconv.ParseInt(tidStr, 10, 64); err == nil {
			return tid
		}
	}

	// 2. 性能优化点：仅针对有 Body 的方法尝试解析 JSON
	method := ctx.Request.Method
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch {
		return 0
	}

	// 3. 性能优化点：检查 Content-Type，避免对非 JSON 请求做无用功
	if !strings.Contains(ctx.GetHeader("Content-Type"), "application/json") {
		return 0
	}

	// 4. 读取并解析 Body
	bodyBytes, err := io.ReadAll(io.LimitReader(ctx.Request.Body, 1024*1024))
	if err == nil {
		// 回放 Body 确保后续 Handler 可读
		ctx.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		var bodyMap map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &bodyMap); err == nil {
			if v, ok := bodyMap["tenant_id"]; ok {
				switch val := v.(type) {
				case float64:
					return int64(val)
				case string:
					tid, _ := strconv.ParseInt(val, 10, 64)
					return tid
				}
			}
		}
	}

	return 0
}

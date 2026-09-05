package middleware

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	auditevt "github.com/Duke1616/eiam/internal/event/audit"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/ecodeclub/ginx/gctx"
	"github.com/ecodeclub/ginx/session"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

// ==========================================
// 1. 配置与规则匹配器 (Rules & Matcher)
// ==========================================

// AuditConfig 审计配置 DTO (纯粹数据定义，映射配置文件)
type AuditConfig struct {
	Enabled       bool     `mapstructure:"enabled"`
	Methods       []string `mapstructure:"methods"`
	IgnoreActions []string `mapstructure:"ignore_actions"`
}

// DefaultAuditConfig 默认审计配置 (开箱即用：默认审计写操作，业务免审完全由代码级 NoAudit 显式驱动)
func DefaultAuditConfig() AuditConfig {
	return AuditConfig{
		Enabled: true,
		Methods: []string{
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodPatch,
		},
	}
}

// IAuditMatcher 审计规则匹配器契约 (面向接口编程，解耦业务 Handler 与中间件)
type IAuditMatcher interface {
	ShouldAuditMethod(method string) bool
	IsIgnoredPath(path string) bool
	IsIgnoredAction(action string) bool
}

type auditMatcher struct {
	enabled       bool
	methodSet     map[string]struct{}
	ignoreActions map[string]struct{}
}

// NewAuditMatcher 编译规则并构建只读高性能匹配器 (O(1) 哈希索引，零内存分配)
func NewAuditMatcher(cfg AuditConfig) IAuditMatcher {
	methodSet := make(map[string]struct{}, len(cfg.Methods))
	for _, m := range cfg.Methods {
		methodSet[strings.ToUpper(strings.TrimSpace(m))] = struct{}{}
	}

	ignoreActions := make(map[string]struct{}, len(cfg.IgnoreActions))
	for _, a := range cfg.IgnoreActions {
		action := strings.TrimSpace(a)
		if action != "" {
			ignoreActions[action] = struct{}{}
		}
	}

	return &auditMatcher{
		enabled:       cfg.Enabled,
		methodSet:     methodSet,
		ignoreActions: ignoreActions,
	}
}

func (m *auditMatcher) ShouldAuditMethod(method string) bool {
	if !m.enabled {
		return false
	}
	if method == http.MethodOptions || method == http.MethodHead {
		return false
	}
	if _, ok := m.methodSet[method]; ok {
		return true
	}
	_, ok := m.methodSet[strings.ToUpper(method)]
	return ok
}

func (m *auditMatcher) IsIgnoredPath(path string) bool {
	// 系统保留免审接口 (自发现与审计回流防死循环)
	return strings.HasPrefix(path, "/api/permission") ||
		strings.HasPrefix(path, "/api/audit") ||
		strings.HasPrefix(path, "/api/discovery")
}

func (m *auditMatcher) IsIgnoredAction(action string) bool {
	if action == "" {
		return false
	}
	_, ok := m.ignoreActions[action]
	return ok
}

// ==========================================
// 2. 强类型异步写入器 (Async Recorder & Worker)
// ==========================================

// IAuditRecorder 操作审计写入器契约
type IAuditRecorder interface {
	Record(log domain.OperationLog)
}

type asyncRecorder struct {
	producer auditevt.IAuditProducer
	queue    chan domain.OperationLog
	dropped  atomic.Uint64
}

func newAsyncRecorder(producer auditevt.IAuditProducer, bufferSize int) *asyncRecorder {
	r := &asyncRecorder{
		producer: producer,
		queue:    make(chan domain.OperationLog, bufferSize),
	}
	go r.worker()
	return r
}

func (r *asyncRecorder) Record(log domain.OperationLog) {
	select {
	case r.queue <- log:
	default:
		r.dropped.Add(1)
	}
}

func (r *asyncRecorder) worker() {
	for log := range r.queue {
		func() {
			defer func() { _ = recover() }()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = r.producer.RecordOperation(ctx, log)
		}()
	}
}

// ==========================================
// 3. 中间件建造者与切面 (Middleware Builder)
// ==========================================

// AuditBuilder 审计切面建造者
type AuditBuilder struct {
	recorder IAuditRecorder
	matcher  IAuditMatcher
}

// NewAuditBuilder 实例化构建器
func NewAuditBuilder(producer auditevt.IAuditProducer, matcher IAuditMatcher) *AuditBuilder {
	return &AuditBuilder{
		recorder: newAsyncRecorder(producer, 1024),
		matcher:  matcher,
	}
}

// WithRecorder 注入自定义记录器 (用于测试或扩展)
func (b *AuditBuilder) WithRecorder(r IAuditRecorder) *AuditBuilder {
	if r != nil {
		b.recorder = r
	}
	return b
}

// Build 生成无侵入轻量 Gin 拦截器 (100% 纯粹操作审计，杜绝任何业务特判)
func (b *AuditBuilder) Build() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		path := ctx.Request.URL.Path

		// 前置放行检查：未启用或免审接口直接执行下游业务
		if !b.matcher.ShouldAuditMethod(ctx.Request.Method) || b.matcher.IsIgnoredPath(path) {
			ctx.Next()
			return
		}

		startTime := time.Now()
		ctx.Next()

		// 检查能力元数据是否显式标记免操作审计 (如会话切换、内部探针)
		ptr := reflect.ValueOf(ctx.Handler()).Pointer()
		if info, ok := capability.GetResourceInfo(ptr); ok && info.NoAudit {
			return
		}

		log := extractOperationLog(ctx, startTime)
		if b.matcher.IsIgnoredAction(log.Action) {
			return
		}

		b.recorder.Record(log)
	}
}

// Audit 全站统一安全审计切面便捷门面
func Audit(producer auditevt.IAuditProducer, opts ...any) gin.HandlerFunc {
	matcher := NewAuditMatcher(DefaultAuditConfig())
	for _, opt := range opts {
		switch v := opt.(type) {
		case IAuditMatcher:
			matcher = v
		case AuditConfig:
			matcher = NewAuditMatcher(v)
		}
	}
	return NewAuditBuilder(producer, matcher).Build()
}

// ==========================================
// 4. 纯函数上下文提取 (Context Extractors)
// ==========================================

func extractOperationLog(ctx *gin.Context, startTime time.Time) domain.OperationLog {
	uid, tid, username := extractIdentity(ctx)
	module, action, name, urn := matchCapability(ctx)
	status, failReason := evaluateStatus(ctx)

	return domain.OperationLog{
		TenantID:     tid,
		Service:      "eiam",
		OperatorID:   uid,
		OperatorName: username,
		Module:       module,
		Action:       action,
		ResourceID:   capability.ExtractResourceParam(ctx),
		ResourceName: name,
		ResourceURN:  urn,
		Status:       status,
		FailReason:   failReason,
		ClientIP:     ctx.ClientIP(),
		UserAgent:    ctx.Request.UserAgent(),
		Ctime:        startTime.UnixMilli(),
	}
}

func evaluateStatus(ctx *gin.Context) (string, string) {
	var err error
	if len(ctx.Errors) > 0 {
		err = ctx.Errors.Last()
	}
	return capability.EvaluateHTTPStatus(ctx.Writer.Status(), err)
}

func extractIdentity(ctx *gin.Context) (uid int64, tid int64, username string) {
	defer func() {
		_ = recover()
	}()
	gCtx := &gctx.Context{Context: ctx}
	if sess, err := session.Get(gCtx); err == nil && sess != nil {
		claims := sess.Claims()
		uid = claims.Uid
		tid, _ = claims.Get("tenant_id").AsInt64()
		username, _ = claims.Get("username").AsString()
	}
	return
}

func matchCapability(ctx *gin.Context) (module, action, name, urn string) {
	method := ctx.Request.Method
	path := ctx.Request.URL.Path

	ptr := reflect.ValueOf(ctx.Handler()).Pointer()
	info, ok := capability.GetResourceInfo(ptr)
	if !ok {
		return "system", method, path, capability.BuildApiURN("iam", method, path)
	}

	module = lo.CoalesceOrEmpty(info.Group, "system")
	action = lo.CoalesceOrEmpty(info.Code, method)
	name = lo.CoalesceOrEmpty(info.Name, path)
	urn = capability.BuildApiURN(info.Service, method, path)
	return
}

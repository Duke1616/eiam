package capability

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/Duke1616/eiam/pkg/pbac"
	"github.com/gin-gonic/gin"
	"github.com/samber/lo"
)

// Capability 代表一个纯粹的业务逻辑能力包（权限中台的核心治理单元）
// 它与具体的物理 API 路由解耦，支持将 1 个或多个物理 API 挂载至自身名下
type Capability struct {
	reg                  *registry
	perm                 *Permission
	defaultFilterProfile pbac.FilterProfile
}

func newCapability(reg *registry, perm *Permission) *Capability {
	return &Capability{
		reg:  reg,
		perm: perm,
	}
}

// Permission 返回当前逻辑能力包的只读快照
func (c *Capability) Permission() Permission {
	c.reg.store.mu.RLock()
	defer c.reg.store.mu.RUnlock()
	return *c.perm
}

// Code 获取能力唯一编码
func (c *Capability) Code() string {
	return c.perm.Code
}

// Name 获取能力展示名称
func (c *Capability) Name() string {
	return c.perm.Name
}

// Group 设置能力所属的分组路径（如 "脚本引擎/版本管理"）
func (c *Capability) Group(group string) *Capability {
	c.reg.store.mu.Lock()
	defer c.reg.store.mu.Unlock()
	c.perm.Group = group
	return c
}

// Needs 声明此能力依赖的其他权限能力码（支持依赖展开与前置检查，支持本地简短码如 "get" 或全权限码）
func (c *Capability) Needs(codes ...string) *Capability {
	c.reg.store.mu.Lock()
	defer c.reg.store.mu.Unlock()
	normalized := lo.Map(codes, func(code string, _ int) string {
		return c.reg.normalizeCode(code)
	})
	c.perm.Needs = lo.Uniq(append(c.perm.Needs, normalized...))
	return c
}

// NoSync 标记当前能力不向 IAM 权限树暴露（通常用于纯从属或内部静默接口）
func (c *Capability) NoSync() *Capability {
	c.reg.store.mu.Lock()
	defer c.reg.store.mu.Unlock()
	c.perm.NoSync = true
	return c
}

// NoAudit 标记当前能力免操作审计 (如登录、租户切换等已有认证审计或系统内部接口)
func (c *Capability) NoAudit() *Capability {
	c.reg.store.mu.Lock()
	defer c.reg.store.mu.Unlock()
	c.perm.NoAudit = true
	return c
}

// Scope 设置能力生效的边界作用域（ScopeTenant 或 ScopeSystem）
func (c *Capability) Scope(scope string) *Capability {
	c.reg.store.mu.Lock()
	defer c.reg.store.mu.Unlock()
	c.perm.Scope = scope
	return c
}

// AccessScope 声明当前能力绑定的数据范围编译 profile 与预设模板
func (c *Capability) AccessScope(profile pbac.FilterProfile, presets ...pbac.AccessScopePreset) *Capability {
	cleaned := validateAccessScope(profile, presets)

	c.reg.store.mu.Lock()
	defer c.reg.store.mu.Unlock()
	c.defaultFilterProfile = profile
	c.perm.AccessScopePresets = cleaned
	return c
}

func validateAccessScope(profile pbac.FilterProfile, presets []pbac.AccessScopePreset) []pbac.AccessScopePreset {
	if strings.TrimSpace(string(profile)) == "" {
		panic("权限能力的数据范围过滤规则不能为空")
	}

	cleaned := lo.Map(presets, func(p pbac.AccessScopePreset, _ int) pbac.AccessScopePreset {
		p.Code = strings.TrimSpace(p.Code)
		p.Name = strings.TrimSpace(p.Name)
		if p.Code == "" || p.Name == "" || p.Expression == nil {
			panic("数据范围预设模板必须包含编码 (code)、名称 (name) 与表达式 (expression)")
		}
		if err := pbac.ValidateAccessScope(p.Expression); err != nil {
			panic(fmt.Sprintf("无效的数据范围预设模板 %s: %v", p.Code, err))
		}
		return p
	})

	// 快速查重，消除手写 seen map
	if dupes := lo.FindDuplicatesBy(cleaned, func(p pbac.AccessScopePreset) string { return p.Code }); len(dupes) > 0 {
		panic("重复定义的数据范围预设模板: " + dupes[0].Code)
	}

	return cleaned
}

// Bind 将路由直接挂载至当前能力（API 名称默认沿用当前能力的名称）
// 这是多 API 聚合到一个能力包时最常用的极简写法
func (c *Capability) Bind(h gin.HandlerFunc) gin.HandlerFunc {
	return c.BindNamed(c.perm.Name, h)
}

// BindNamed 将路由挂载至当前能力，并赋予该物理 API 独立的名称
// 例如同一能力包下，一个接口命名为 "用户列表"，另一个命名为 "用户详情"
func (c *Capability) BindNamed(apiName string, h gin.HandlerFunc) gin.HandlerFunc {
	return c.Route(WithName(apiName)).Handle(h)
}

// Route 开启细粒度路由绑定修饰（如允许跨租户访问或自定义 API 级属性）
func (c *Capability) Route(opts ...RouteOption) *RouteBinding {
	rb := &RouteBinding{
		cap:           c,
		apiName:       c.perm.Name,
		filterProfile: c.defaultFilterProfile,
	}
	for _, opt := range opts {
		opt(rb)
	}
	return rb
}

// --- RouteBinding 路由修饰与最终装载 ---

// RouteOption 物理路由选项
type RouteOption func(*RouteBinding)

func WithName(name string) RouteOption {
	return func(rb *RouteBinding) { rb.apiName = name }
}

func WithCrossTenant() RouteOption {
	return func(rb *RouteBinding) { rb.allowCrossTenant = true }
}

func WithNoAudit() RouteOption {
	return func(rb *RouteBinding) { rb.noAudit = true }
}

// RouteBinding 物理路由与逻辑能力包的关联器
type RouteBinding struct {
	cap              *Capability
	apiName          string
	allowCrossTenant bool
	noAudit          bool
	filterProfile    pbac.FilterProfile
}

func (rb *RouteBinding) AllowCrossTenant() *RouteBinding {
	rb.allowCrossTenant = true
	return rb
}

func (rb *RouteBinding) NoAudit() *RouteBinding {
	rb.noAudit = true
	return rb
}

func (rb *RouteBinding) Name(name string) *RouteBinding {
	rb.apiName = name
	return rb
}

// Handle 装饰 Gin Handler，完成物理接口与权限元数据的最终绑定
func (rb *RouteBinding) Handle(h gin.HandlerFunc) gin.HandlerFunc {
	ptr := reflect.ValueOf(h).Pointer()

	rb.cap.reg.store.mu.RLock()
	noAudit := rb.noAudit || rb.cap.perm.NoAudit
	info := ResourceInfo{
		Service:          rb.cap.perm.Service,
		Name:             rb.apiName,
		Code:             rb.cap.perm.Code,
		Needs:            slices.Clone(rb.cap.perm.Needs),
		Group:            rb.cap.perm.Group,
		NoAudit:          noAudit,
		AllowCrossTenant: rb.allowCrossTenant,
		FilterProfile:    rb.filterProfile,
	}
	rb.cap.reg.store.mu.RUnlock()

	DefaultRuntime().Register(ptr, info)
	return h
}

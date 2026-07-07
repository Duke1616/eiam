package capability

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
)

// SyncRequest 定义了 SDK 上报资产给 EIAM 的标准协议 (Snapshot)
type SyncRequest struct {
	Source      string         `json:"source,omitempty"`
	Service     string         `json:"service"`
	Permissions []Permission   `json:"permissions"`
	APIs        []ResourceInfo `json:"apis"`
	Menus       []Menu         `json:"menus"`
}

func (r SyncRequest) OwnerKey() string {
	if r.Source == "" {
		return r.Service
	}
	return r.Service + "@" + r.Source
}

// Hash 计算资产快照的稳定哈希值
func (r *SyncRequest) Hash() string {
	// 1. 深度标准化（确保排序稳定且不影响原始数据）
	r.normalize()

	// 2. 序列化并计算哈希
	b, _ := json.Marshal(r)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// normalize 对请求体内的所有资产进行确定性排序
func (r *SyncRequest) normalize() {
	// 排序逻辑：
	// Permission 按 Code 升序
	slices.SortFunc(r.Permissions, func(a, b Permission) int { return cmp.Compare(a.Code, b.Code) })

	// API 按 Path 升序，Path 相同按 Method 升序
	slices.SortFunc(r.APIs, func(a, b ResourceInfo) int {
		if r := cmp.Compare(a.Path, b.Path); r != 0 {
			return r
		}
		return cmp.Compare(a.Method, b.Method)
	})

	// Menu 按 Name 升序
	slices.SortFunc(r.Menus, func(a, b Menu) int { return cmp.Compare(a.Name, b.Name) })
}

// Registry 资产注册底层的持久化或传输契约
type Registry interface {
	Sync(ctx context.Context, req SyncRequest) error
}

// Syncer 资产同步 SDK 的核心交互接口 (Facade Pattern)
type Syncer interface {
	// WithOption 动态追加同步选项 (如追加 Provider 或 Router)
	WithOption(opts ...SyncOption) Syncer
	// Sync 执行全量扫描与上报闭环
	Sync(ctx context.Context) error
}

type defaultSyncer struct {
	registry  Registry
	collector *Collector
}

// NewSyncer 构造函数，支持预设同步选项
// Service 从 Collector 收集的 Permission/ResourceInfo 中自动推导，无需显式传递
func NewSyncer(registry Registry, opts ...SyncOption) Syncer {
	s := &defaultSyncer{
		registry:  registry,
		collector: NewCollector(),
	}

	// 应用初始选项
	if len(opts) > 0 {
		s.WithOption(opts...)
	}

	return s
}

func (s *defaultSyncer) WithOption(opts ...SyncOption) Syncer {
	for _, opt := range opts {
		opt(s.collector)
	}
	return s
}

func (s *defaultSyncer) Sync(ctx context.Context) error {
	// 资产收集：Collector.Collect() 自动推导 Service
	req := s.collector.Collect()
	return s.registry.Sync(ctx, req)
}

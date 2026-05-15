package capability

import (
	"context"
)

// SyncRequest 定义了 SDK 上报资产给 EIAM 的标准协议 (Snapshot)
type SyncRequest struct {
	Service     string         `json:"service"`
	Permissions []Permission   `json:"permissions"`
	APIs        []ResourceInfo `json:"apis"`
	Menus       []Menu         `json:"menus"`
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
	service   string
	registry  Registry
	collector *Collector
}

// NewSyncer 构造函数，支持预设同步选项
func NewSyncer(service string, registry Registry, opts ...SyncOption) Syncer {
	s := &defaultSyncer{
		service:   service,
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
	// 1. 资产收集：利用持有的 Collector 聚合所有类型的资产
	req := s.collector.Collect()
	req.Service = s.service

	// 2. 执行报备
	return s.registry.Sync(ctx, req)
}

package syncer

import (
	"context"

	"github.com/Duke1616/eiam/pkg/web/capability"
)

// Reporter 资产上报契约
type Reporter = capability.Reporter

// Registry 兼容历史别名
type Registry = capability.Registry

// Syncer 资产同步调度引擎接口
type Syncer interface {
	WithOption(opts ...capability.SyncOption) Syncer
	Sync(ctx context.Context) error
}

type defaultSyncer struct {
	reporter  capability.Reporter
	collector *capability.Collector
}

// New 构造函数，调度 Collector 收集资产并上报
func New(reporter capability.Reporter, opts ...capability.SyncOption) Syncer {
	s := &defaultSyncer{
		reporter:  reporter,
		collector: capability.NewCollector(),
	}
	if len(opts) > 0 {
		s.WithOption(opts...)
	}
	return s
}

func (s *defaultSyncer) WithOption(opts ...capability.SyncOption) Syncer {
	for _, opt := range opts {
		opt(s.collector)
	}
	return s
}

func (s *defaultSyncer) Sync(ctx context.Context) error {
	req := s.collector.Collect()
	return s.reporter.Sync(ctx, req)
}

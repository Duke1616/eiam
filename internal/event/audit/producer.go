package audit

import (
	"context"
	"fmt"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/pkg/redisx"
	"github.com/gotomicro/ego/core/elog"
	"github.com/redis/go-redis/v9"
)

//go:generate mockgen -package=auditmocks -destination=./mocks/producer.mock.go github.com/Duke1616/eiam/internal/event/audit IAuditProducer

// IAuditProducer 审计日志生产者接口契约
type IAuditProducer interface {
	// Produce 发布底层审计事件
	Produce(ctx context.Context, evt Event) error
	// RecordAuth 快速发布认证安全审计
	RecordAuth(ctx context.Context, log domain.AuthLog) error
	// RecordOperation 快速发布业务管理操作审计
	RecordOperation(ctx context.Context, log domain.OperationLog) error
}

type producer struct {
	queue  redisx.IStreamQueue[Event]
	logger *elog.Component
}

// NewProducer 构建审计事件生产者，直接对接泛型 Redis Stream 消息队列基础设施
func NewProducer(client redis.Cmdable) IAuditProducer {
	return NewProducerWithQueue(redisx.NewStreamQueue[Event](client))
}

// NewProducerWithQueue 使用自定义泛型流队列构建生产者 (用于测试解耦)
func NewProducerWithQueue(queue redisx.IStreamQueue[Event]) IAuditProducer {
	return &producer{
		queue:  queue,
		logger: elog.DefaultLogger.With(elog.FieldComponent("audit.producer")),
	}
}

// Produce 投递强类型审计事件到流存储 (由底层队列自动完成序列化)
func (p *producer) Produce(ctx context.Context, evt Event) error {
	if _, err := p.queue.Publish(ctx, StreamName, evt, redisx.WithMaxLen(MaxStreamLength)); err != nil {
		p.logger.Warn("投递审计事件到流存储失败", elog.FieldErr(err), elog.String("type", evt.Type))
		return fmt.Errorf("投递审计事件失败: %w", err)
	}
	return nil
}

// RecordAuth 发布认证审计
func (p *producer) RecordAuth(ctx context.Context, log domain.AuthLog) error {
	return p.Produce(ctx, NewAuthEvent(log))
}

// RecordOperation 发布操作审计
func (p *producer) RecordOperation(ctx context.Context, log domain.OperationLog) error {
	return p.Produce(ctx, NewOperationEvent(log))
}

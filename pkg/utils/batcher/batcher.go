package batcher

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Option 批处理器配置选项
type Option[T any] func(*Batcher[T])

// WithBatchSize 配置单批次最大容量
func WithBatchSize[T any](size int) Option[T] {
	return func(b *Batcher[T]) {
		if size > 0 {
			b.batchSize = size
		}
	}
}

// WithBufferCap 配置内存通道最大队列容量
func WithBufferCap[T any](capacity int) Option[T] {
	return func(b *Batcher[T]) {
		if capacity > 0 {
			b.bufferCap = capacity
		}
	}
}

// WithFlushInterval 配置定时强刷间隔
func WithFlushInterval[T any](interval time.Duration) Option[T] {
	return func(b *Batcher[T]) {
		if interval > 0 {
			b.flushInterval = interval
		}
	}
}

// FlushFunc 批量消费回调函数
type FlushFunc[T any] func(ctx context.Context, batch []T) error

// Batcher 通用高性能非阻塞异步批聚合引擎
// 具备内存环形缓冲、定时定量双触发调度、Fail-Safe 丢弃保护与优雅停机能力
type Batcher[T any] struct {
	batchSize     int
	bufferCap     int
	flushInterval time.Duration
	flushFn       FlushFunc[T]

	queue       chan T
	dropCounter atomic.Uint64
	done        chan struct{}
	wg          sync.WaitGroup
	closeOnce   sync.Once
}

// NewBatcher 构建并启动异步批处理器
func NewBatcher[T any](flushFn FlushFunc[T], opts ...Option[T]) *Batcher[T] {
	b := &Batcher[T]{
		batchSize:     50,
		bufferCap:     2000,
		flushInterval: 500 * time.Millisecond,
		flushFn:       flushFn,
		done:          make(chan struct{}),
	}

	for _, opt := range opts {
		opt(b)
	}

	b.queue = make(chan T, b.bufferCap)
	b.wg.Add(1)
	go b.scheduler()

	return b
}

// Push 非阻塞投递单个元素，若缓冲区已满或已关闭则触发丢弃保护并返回 false，绝对零阻塞调用方
func (b *Batcher[T]) Push(item T) (pushed bool) {
	defer func() {
		if r := recover(); r != nil {
			pushed = false
			b.dropCounter.Add(1)
		}
	}()
	select {
	case b.queue <- item:
		return true
	default:
		b.dropCounter.Add(1)
		return false
	}
}

// DroppedCount 获取自启动以来被安全丢弃的元素总量 (用于健康检查与监控告警)
func (b *Batcher[T]) DroppedCount() uint64 {
	return b.dropCounter.Load()
}

// scheduler 调度核心：结合通道事件与定时器实现双触发批处理
func (b *Batcher[T]) scheduler() {
	defer b.wg.Done()

	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	batch := make([]T, 0, b.batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		// 独立上下文避免受外部中断影响
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = b.flushFn(ctx, batch)
		cancel()
		batch = make([]T, 0, b.batchSize)
	}

	for {
		select {
		case item, ok := <-b.queue:
			if !ok {
				// 通道关闭，刷出尾部残余数据后退出
				flush()
				return
			}
			batch = append(batch, item)
			if len(batch) >= b.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// Close 优雅停止批处理器：关闭队列、等待积压数据全部刷出 (幂等安全，多次调用无副作用)
func (b *Batcher[T]) Close() {
	b.closeOnce.Do(func() {
		close(b.queue)
		b.wg.Wait()
	})
}

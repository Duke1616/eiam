package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/repository"
	"github.com/Duke1616/eiam/pkg/gormx"
	"github.com/Duke1616/eiam/pkg/redisx"
	"github.com/gotomicro/ego/core/elog"
	"github.com/redis/go-redis/v9"
	"github.com/samber/lo"
)

// Consumer 审计日志消费处理器，实现 ioc.Task 接口
type Consumer struct {
	queue         redisx.IStreamQueue[Event]
	deadLetter    redisx.IStreamQueue[DeadLetterEvent]
	repo          repository.IAuditRepository
	logger        *elog.Component
	consumerName  string
	batchSize     int
	flushInterval time.Duration
}

// NewConsumer 构建审计消费者实例
func NewConsumer(client redis.Cmdable, repo repository.IAuditRepository) *Consumer {
	return NewConsumerWithQueue(
		redisx.NewStreamQueue[Event](client),
		redisx.NewStreamQueue[DeadLetterEvent](client),
		repo,
	)
}

// NewConsumerWithQueue 使用自定义流队列构建消费者实例 (用于测试解耦)
func NewConsumerWithQueue(
	queue redisx.IStreamQueue[Event],
	deadLetter redisx.IStreamQueue[DeadLetterEvent],
	repo repository.IAuditRepository,
) *Consumer {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "eiam-node"
	}

	return &Consumer{
		queue:         queue,
		deadLetter:    deadLetter,
		repo:          repo,
		logger:        elog.DefaultLogger.With(elog.FieldComponent("audit.consumer")),
		consumerName:  fmt.Sprintf("%s-%d", hostname, time.Now().UnixNano()%10000),
		batchSize:     DefaultBatchSize,
		flushInterval: DefaultFlushInterval,
	}
}

// Start 启动后台消费调度循环 (实现 ioc.Task 接口)
func (c *Consumer) Start(ctx context.Context) {
	if err := c.queue.InitGroup(ctx, StreamName, ConsumerGroup); err != nil {
		c.logger.Warn("初始化审计消息流消费组异常", elog.FieldErr(err))
	}
	go c.consumeLoop(ctx)
}

// consumeLoop 核心拉取与批处理聚合调度循环
func (c *Consumer) consumeLoop(ctx context.Context) {
	c.logger.Info("审计消费 Worker 已启动", elog.String("consumer", c.consumerName))

	var (
		buffer      = newBatchBuffer(c.batchSize)
		flushTicker = time.NewTicker(c.flushInterval)
		claimTicker = time.NewTicker(1 * time.Minute)
	)
	defer flushTicker.Stop()
	defer claimTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("审计消费 Worker 收到退出信号，执行剩余日志刷盘")
			c.flush(buffer)
			return
		case <-flushTicker.C:
			c.flush(buffer)
		case <-claimTicker.C:
			c.claimPending(ctx, buffer)
		default:
			c.pollStream(ctx, buffer)
		}
	}
}

// pollStream 从 Stream 拉取待处理强类型消息批次
func (c *Consumer) pollStream(ctx context.Context, buffer *batchBuffer) {
	messages, err := c.queue.ReadGroup(ctx, StreamName, ConsumerGroup, c.consumerName, int64(c.batchSize), 200*time.Millisecond)
	if err != nil {
		if !errors.Is(err, redis.Nil) && ctx.Err() == nil {
			c.logger.Warn("读取审计流消息失败", elog.FieldErr(err))
			time.Sleep(200 * time.Millisecond)
		}
		return
	}

	c.collectMessages(ctx, messages, buffer)
}

// claimPending 认领 PEL 中因节点故障遗留的超时未确认消息
func (c *Consumer) claimPending(ctx context.Context, buffer *batchBuffer) {
	messages, _, err := c.queue.AutoClaim(ctx, StreamName, ConsumerGroup, c.consumerName, time.Minute, "0-0", int64(c.batchSize))
	if err != nil {
		return
	}
	c.collectMessages(ctx, messages, buffer)
}

// collectMessages 聚合强类型消息到缓冲区，捕获损坏消息并分流死信
func (c *Consumer) collectMessages(ctx context.Context, messages []redisx.Message[Event], buffer *batchBuffer) {
	for _, msg := range messages {
		// 若消息反序列化失败或格式损坏 (毒丸消息)，直接转储死信队列并标记为损坏以完成 ACK
		if msg.Err != nil {
			c.logger.Error("审计消息载荷解析失败", elog.FieldErr(msg.Err), elog.String("msgID", msg.ID))
			c.sendToDeadLetter(ctx, msg.ID, msg.RawValues, msg.Err.Error())
			buffer.AddCorrupted(msg.ID)
			continue
		}

		evt := msg.Payload
		if evt.Type == EventTypeAuth && evt.AuthLog != nil {
			buffer.AddAuth(msg.ID, *evt.AuthLog, evt)
		} else if evt.Type == EventTypeOperation && evt.OperationLog != nil {
			buffer.AddOp(msg.ID, *evt.OperationLog, evt)
		} else {
			// 未知事件类型，标记为损坏消息
			buffer.AddCorrupted(msg.ID)
		}

		if buffer.IsFull() {
			c.flush(buffer)
		}
	}
}

// flush 执行当前缓冲区的批量入库与 ACK，支持降级重试与死信转储
func (c *Consumer) flush(buffer *batchBuffer) {
	if buffer.IsEmpty() {
		return
	}

	flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 消费 Worker 属于后台系统任务，显式提权绕过多租户阻断拦截
	flushCtx = gormx.IgnoreTenantContext(flushCtx)

	// 分段处理：认证日志与操作日志独立持久化与 ACK，互不干扰
	if len(buffer.authItems) > 0 {
		c.flushAuthBatch(flushCtx, buffer.authItems)
	}

	if len(buffer.opItems) > 0 {
		c.flushOpBatch(flushCtx, buffer.opItems)
	}

	if len(buffer.corruptedMsgIDs) > 0 {
		c.ackBatch(flushCtx, buffer.corruptedMsgIDs)
	}

	buffer.Reset()
}

// flushAuthBatch 批量写入认证日志，失败时降级为单条入库并转储死信
func (c *Consumer) flushAuthBatch(ctx context.Context, items []pendingAuthItem) {
	logs := lo.Map(items, func(item pendingAuthItem, _ int) domain.AuthLog {
		return item.log
	})

	if err := c.repo.BatchSaveAuthLogs(ctx, logs); err == nil {
		c.ackBatch(ctx, lo.Map(items, func(item pendingAuthItem, _ int) string { return item.msgID }))
		return
	} else {
		c.logger.Warn("批量写入认证审计日志异常，进入单条降级重试模式", elog.FieldErr(err), elog.Int("count", len(items)))
	}

	var ackIDs []string
	for _, item := range items {
		if err := c.repo.BatchSaveAuthLogs(ctx, []domain.AuthLog{item.log}); err != nil {
			c.logger.Error("认证审计单条入库失败，转入死信队列", elog.FieldErr(err), elog.String("msgID", item.msgID))
			c.sendToDeadLetter(ctx, item.msgID, item.rawEvent, err.Error())
		}
		ackIDs = append(ackIDs, item.msgID)
	}

	c.ackBatch(ctx, ackIDs)
}

// flushOpBatch 批量写入操作日志，失败时降级为单条入库并转储死信
func (c *Consumer) flushOpBatch(ctx context.Context, items []pendingOpItem) {
	logs := lo.Map(items, func(item pendingOpItem, _ int) domain.OperationLog {
		return item.log
	})

	if err := c.repo.BatchSaveOperationLogs(ctx, logs); err == nil {
		c.ackBatch(ctx, lo.Map(items, func(item pendingOpItem, _ int) string { return item.msgID }))
		return
	} else {
		c.logger.Warn("批量写入操作审计日志异常，进入单条降级重试模式", elog.FieldErr(err), elog.Int("count", len(items)))
	}

	var ackIDs []string
	for _, item := range items {
		if err := c.repo.BatchSaveOperationLogs(ctx, []domain.OperationLog{item.log}); err != nil {
			c.logger.Error("操作审计单条入库失败，转入死信队列", elog.FieldErr(err), elog.String("msgID", item.msgID))
			c.sendToDeadLetter(ctx, item.msgID, item.rawEvent, err.Error())
		}
		ackIDs = append(ackIDs, item.msgID)
	}

	c.ackBatch(ctx, ackIDs)
}

// ackBatch 批量确认流消息
func (c *Consumer) ackBatch(ctx context.Context, msgIDs []string) {
	if len(msgIDs) == 0 {
		return
	}
	ackIDs := lo.Uniq(msgIDs)
	if err := c.queue.Ack(ctx, StreamName, ConsumerGroup, ackIDs...); err != nil {
		c.logger.Warn("确认审计流消息异常", elog.FieldErr(err), elog.Int("count", len(ackIDs)))
	}
}

// sendToDeadLetter 将无法消费的消息转存到死信流
func (c *Consumer) sendToDeadLetter(ctx context.Context, msgID string, raw any, reason string) {
	payloadStr, _ := json.Marshal(raw)
	dlEvt := DeadLetterEvent{
		OriginalMsgID: msgID,
		Reason:        reason,
		Payload:       string(payloadStr),
		FailedAt:      time.Now().UnixMilli(),
	}

	if _, err := c.deadLetter.Publish(ctx, DeadLetterStreamName, dlEvt, redisx.WithMaxLen(MaxStreamLength)); err != nil {
		c.logger.Error("投递死信事件失败", elog.FieldErr(err), elog.String("msgID", msgID))
	}
}

type pendingAuthItem struct {
	msgID    string
	log      domain.AuthLog
	rawEvent any
}

type pendingOpItem struct {
	msgID    string
	log      domain.OperationLog
	rawEvent any
}

// batchBuffer 批处理聚合缓冲区
type batchBuffer struct {
	capacity        int
	authItems       []pendingAuthItem
	opItems         []pendingOpItem
	corruptedMsgIDs []string
}

func newBatchBuffer(capacity int) *batchBuffer {
	return &batchBuffer{
		capacity:        capacity,
		authItems:       make([]pendingAuthItem, 0, capacity),
		opItems:         make([]pendingOpItem, 0, capacity),
		corruptedMsgIDs: make([]string, 0, capacity),
	}
}

func (b *batchBuffer) AddAuth(msgID string, log domain.AuthLog, rawEvent any) {
	b.authItems = append(b.authItems, pendingAuthItem{
		msgID:    msgID,
		log:      log,
		rawEvent: rawEvent,
	})
}

func (b *batchBuffer) AddOp(msgID string, log domain.OperationLog, rawEvent any) {
	b.opItems = append(b.opItems, pendingOpItem{
		msgID:    msgID,
		log:      log,
		rawEvent: rawEvent,
	})
}

func (b *batchBuffer) AddCorrupted(msgID string) {
	b.corruptedMsgIDs = append(b.corruptedMsgIDs, msgID)
}

func (b *batchBuffer) IsFull() bool {
	return len(b.authItems)+len(b.opItems)+len(b.corruptedMsgIDs) >= b.capacity
}

func (b *batchBuffer) IsEmpty() bool {
	return len(b.authItems) == 0 && len(b.opItems) == 0 && len(b.corruptedMsgIDs) == 0
}

func (b *batchBuffer) Reset() {
	b.authItems = b.authItems[:0]
	b.opItems = b.opItems[:0]
	b.corruptedMsgIDs = b.corruptedMsgIDs[:0]
}

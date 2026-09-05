package redisx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/samber/lo"
)

const DefaultPayloadKey = "payload"

// Message 泛型流消息实体，携带消息ID、强类型载荷与底层原始键值
type Message[T any] struct {
	ID        string         // Redis Stream 消息唯一 ID (如 "1710000000000-0")
	Payload   T              // 反序列化后的领域业务数据
	RawValues map[string]any // Redis Stream 原始键值映射
	Err       error          // 若反序列化异常或字段损坏，记录错误 (便于消费端识别毒丸消息)
}

// Serializer 泛型序列化与反序列化接口契约
type Serializer[T any] interface {
	Marshal(v T) (string, error)
	Unmarshal(data string, v *T) error
}

// JSONSerializer 默认 JSON 序列化器实现
type JSONSerializer[T any] struct{}

func (s JSONSerializer[T]) Marshal(v T) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s JSONSerializer[T]) Unmarshal(data string, v *T) error {
	return json.Unmarshal([]byte(data), v)
}

// PublishOption 消息发布配置选项
type PublishOption func(*publishOptions)

type publishOptions struct {
	maxLen      int64
	approximate bool
	payloadKey  string
	extraValues map[string]any
}

// WithMaxLen 限制 Stream 最大长度，避免 Redis 内存无限增长
func WithMaxLen(maxLen int64) PublishOption {
	return func(o *publishOptions) {
		o.maxLen = maxLen
	}
}

// WithApproximate 指定裁剪是否近似匹配 (~)，大幅提升 Redis 内存裁剪性能
func WithApproximate(approx bool) PublishOption {
	return func(o *publishOptions) {
		o.approximate = approx
	}
}

// WithPayloadKey 自定义序列化载荷存储的键名 (默认: "payload")
func WithPayloadKey(key string) PublishOption {
	return func(o *publishOptions) {
		if key != "" {
			o.payloadKey = key
		}
	}
}

// WithExtraValues 携带额外的追踪或审计元数据键值对
func WithExtraValues(kvs map[string]any) PublishOption {
	return func(o *publishOptions) {
		for k, v := range kvs {
			o.extraValues[k] = v
		}
	}
}

// IStreamQueue 泛型 Redis Stream 消息队列契约
//
//go:generate mockgen -package=redisxmocks -destination=./mocks/stream.mock.go github.com/Duke1616/eiam/pkg/redisx IStreamQueue
type IStreamQueue[T any] interface {
	// Publish 发布强类型消息至指定 Stream (自动序列化，返回生成的消息ID)
	Publish(ctx context.Context, stream string, payload T, opts ...PublishOption) (string, error)
	// InitGroup 初始化流消费组 (自动幂等忽略 BUSYGROUP 错误)
	InitGroup(ctx context.Context, stream, group string) error
	// ReadGroup 从消费组批量拉取强类型消息
	ReadGroup(ctx context.Context, stream, group, consumer string, count int64, block time.Duration) ([]Message[T], error)
	// AutoClaim 认领并转换超时未确认的 PEL 孤儿消息
	AutoClaim(ctx context.Context, stream, group, consumer string, minIdle time.Duration, start string, count int64) ([]Message[T], string, error)
	// Ack 批量确认消息
	Ack(ctx context.Context, stream, group string, ids ...string) error
}

type streamQueue[T any] struct {
	client     redis.Cmdable
	serializer Serializer[T]
	payloadKey string
}

// NewStreamQueue 构建通用的泛型 Redis Stream 队列操作实例
func NewStreamQueue[T any](client redis.Cmdable, serializer ...Serializer[T]) IStreamQueue[T] {
	var ser Serializer[T] = JSONSerializer[T]{}
	if len(serializer) > 0 && serializer[0] != nil {
		ser = serializer[0]
	}

	return &streamQueue[T]{
		client:     client,
		serializer: ser,
		payloadKey: DefaultPayloadKey,
	}
}

func (q *streamQueue[T]) Publish(ctx context.Context, stream string, payload T, opts ...PublishOption) (string, error) {
	po := &publishOptions{
		approximate: true,
		payloadKey:  q.payloadKey,
		extraValues: make(map[string]any),
	}
	for _, opt := range opts {
		opt(po)
	}

	dataStr, err := q.serializer.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("序列化消息失败: %w", err)
	}

	values := make(map[string]interface{}, len(po.extraValues)+1)
	for k, v := range po.extraValues {
		values[k] = v
	}
	values[po.payloadKey] = dataStr

	args := &redis.XAddArgs{
		Stream: stream,
		MaxLen: po.maxLen,
		Approx: po.approximate,
		Values: values,
	}

	id, err := q.client.XAdd(ctx, args).Result()
	if err != nil {
		return "", fmt.Errorf("发布消息流失败: %w", err)
	}
	return id, nil
}

func (q *streamQueue[T]) InitGroup(ctx context.Context, stream, group string) error {
	err := q.client.XGroupCreateMkStream(ctx, stream, group, "$").Err()
	if err != nil && strings.Contains(err.Error(), "BUSYGROUP") {
		return nil
	}
	return err
}

func (q *streamQueue[T]) ReadGroup(ctx context.Context, stream, group, consumer string, count int64, block time.Duration) ([]Message[T], error) {
	streams, err := q.client.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    group,
		Consumer: consumer,
		Streams:  []string{stream, ">"},
		Count:    count,
		Block:    block,
	}).Result()
	if err != nil {
		return nil, err
	}

	rawMsgs := lo.FlatMap(streams, func(s redis.XStream, _ int) []redis.XMessage {
		return s.Messages
	})

	return q.parseMessages(rawMsgs), nil
}

func (q *streamQueue[T]) AutoClaim(ctx context.Context, stream, group, consumer string, minIdle time.Duration, start string, count int64) ([]Message[T], string, error) {
	rawMsgs, nextStart, err := q.client.XAutoClaim(ctx, &redis.XAutoClaimArgs{
		Stream:   stream,
		Group:    group,
		Consumer: consumer,
		MinIdle:  minIdle,
		Start:    start,
		Count:    count,
	}).Result()
	if err != nil {
		return nil, "", err
	}

	return q.parseMessages(rawMsgs), nextStart, nil
}

func (q *streamQueue[T]) Ack(ctx context.Context, stream, group string, ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	return q.client.XAck(ctx, stream, group, ids...).Err()
}

// parseMessages 统一将原始 redis.XMessage 转换为强类型的 Message[T]
func (q *streamQueue[T]) parseMessages(messages []redis.XMessage) []Message[T] {
	result := make([]Message[T], 0, len(messages))
	for _, m := range messages {
		msg := Message[T]{
			ID:        m.ID,
			RawValues: m.Values,
		}

		rawVal, ok := m.Values[q.payloadKey]
		if !ok {
			msg.Err = fmt.Errorf("消息缺失 %s 字段", q.payloadKey)
			result = append(result, msg)
			continue
		}

		dataStr, ok := rawVal.(string)
		if !ok {
			msg.Err = errors.New("消息 payload 字段非字符串类型")
			result = append(result, msg)
			continue
		}

		var payload T
		if err := q.serializer.Unmarshal(dataStr, &payload); err != nil {
			msg.Err = fmt.Errorf("反序列化消息载荷失败: %w", err)
			result = append(result, msg)
			continue
		}

		msg.Payload = payload
		result = append(result, msg)
	}
	return result
}

package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/redis/go-redis/v9"
	"github.com/samber/lo"
)

// ISerializer 泛型序列化与反序列化抽象契约
type ISerializer[T any] interface {
	Marshal(val T) ([]byte, error)
	Unmarshal(data []byte, val *T) error
}

// defaultJSONSerializer 默认标准 JSON 编解码器
type defaultJSONSerializer[T any] struct{}

func (s *defaultJSONSerializer[T]) Marshal(val T) ([]byte, error) {
	return json.Marshal(val)
}

func (s *defaultJSONSerializer[T]) Unmarshal(data []byte, val *T) error {
	return json.Unmarshal(data, val)
}

// StateCache 这是一个通用的泛型缓存，用于处理“存入 -> 读取 -> 立即销毁”的临时状态逻辑
type StateCache[T any] struct {
	client     redis.Cmdable
	prefix     string
	ttl        time.Duration
	serializer ISerializer[T]
}

// NewStateCache 创建临时状态通用缓存
func NewStateCache[T any](client redis.Cmdable, prefix string, ttl time.Duration) *StateCache[T] {
	return &StateCache[T]{
		client:     client,
		prefix:     prefix,
		ttl:        ttl,
		serializer: &defaultJSONSerializer[T]{},
	}
}

// Set 存储临时状态
func (c *StateCache[T]) Set(ctx context.Context, key string, val T) error {
	data, err := c.serializer.Marshal(val)
	if err != nil {
		return err
	}
	return c.client.Set(ctx, c.key(key), data, c.ttl).Err()
}

// Get 原子获取并删除临时状态，确保“读后即焚”，彻底杜绝并发重放
func (c *StateCache[T]) Get(ctx context.Context, key string) (T, error) {
	k := c.key(key)
	val, err := c.client.GetDel(ctx, k).Result()
	if err != nil {
		var zero T
		return zero, err
	}

	var res T
	err = c.serializer.Unmarshal(stringToBytes(val), &res)
	return res, err
}

func (c *StateCache[T]) key(key string) string {
	var b strings.Builder
	b.Grow(len("eiam:state:") + len(c.prefix) + 1 + len(key))
	b.WriteString("eiam:state:")
	b.WriteString(c.prefix)
	b.WriteByte(':')
	b.WriteString(key)
	return b.String()
}

// EntityCache 多租户领域实体通用的二级详情泛型缓存组件
type EntityCache[T any] struct {
	client     redis.Cmdable
	prefix     string              // 业务前缀命名空间，如 "role:detail" 或 "policy:detail"
	ttl        time.Duration       // 基准 TTL
	keyFn      func(item T) string // 从实体对象提取唯一标识 Code
	serializer ISerializer[T]      // 可插拔编解码器
}

// NewEntityCache 创建多租户实体详情通用泛型缓存
func NewEntityCache[T any](client redis.Cmdable, prefix string, ttl time.Duration, keyFn func(item T) string) *EntityCache[T] {
	return &EntityCache[T]{
		client:     client,
		prefix:     prefix,
		ttl:        ttl,
		keyFn:      keyFn,
		serializer: &defaultJSONSerializer[T]{},
	}
}

// Key 构建带租户隔离的 Redis Key: eiam:<prefix>:<tid>:<code>
// 采用 strings.Builder 与 strconv 避免 fmt.Sprintf 的反射与多次内存分配开销
func (c *EntityCache[T]) Key(tid int64, code string) string {
	var b strings.Builder
	// 预估容量：len("eiam:") + len(prefix) + 1 + 20(int64) + 1 + len(code)
	b.Grow(len("eiam:") + len(c.prefix) + 22 + len(code))
	b.WriteString("eiam:")
	b.WriteString(c.prefix)
	b.WriteByte(':')
	b.WriteString(strconv.FormatInt(tid, 10))
	b.WriteByte(':')
	b.WriteString(code)
	return b.String()
}

// JitterTTL 增加 ±10% 随机抖动，防止大批量热点实体在同一瞬间集体过期引发缓存雪崩
// 基于 Go 1.22+ math/rand/v2 原生无锁随机源，消除高并发下的全局互斥锁竞争
func (c *EntityCache[T]) JitterTTL() time.Duration {
	if c.ttl <= 0 {
		return c.ttl
	}
	jitterRange := float64(c.ttl) * 0.2 // ±10% 范围共计 20%
	jitter := time.Duration(rand.Float64() * jitterRange)
	base := time.Duration(float64(c.ttl) * 0.9) // 基础为 90%
	return base + jitter
}

// Get 获取单条实体详情；hit 为 true 表示命中缓存
func (c *EntityCache[T]) Get(ctx context.Context, tid int64, code string) (T, bool, error) {
	var zero T
	if code == "" {
		return zero, false, nil
	}

	key := c.Key(tid, code)
	val, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return zero, false, nil
		}
		return zero, false, err
	}

	var res T
	if err = c.serializer.Unmarshal(val, &res); err != nil {
		return zero, false, fmt.Errorf("反序列化实体缓存失败: %w", err)
	}
	return res, true, nil
}

// Set 缓存单条实体详情
func (c *EntityCache[T]) Set(ctx context.Context, tid int64, code string, val T) error {
	if code == "" {
		return nil
	}

	data, err := c.serializer.Marshal(val)
	if err != nil {
		return fmt.Errorf("序列化实体缓存失败: %w", err)
	}

	key := c.Key(tid, code)
	return c.client.Set(ctx, key, data, c.JitterTTL()).Err()
}

// Delete 驱逐单条实体缓存
func (c *EntityCache[T]) Delete(ctx context.Context, tid int64, code string) error {
	if code == "" {
		return nil
	}
	return c.client.Del(ctx, c.Key(tid, code)).Err()
}

// DeleteMulti 批量驱逐多条实体缓存
func (c *EntityCache[T]) DeleteMulti(ctx context.Context, tid int64, codes []string) error {
	keys := lo.Uniq(lo.FilterMap(codes, func(code string, _ int) (string, bool) {
		if code == "" {
			return "", false
		}
		return c.Key(tid, code), true
	}))
	if len(keys) == 0 {
		return nil
	}
	return c.client.Del(ctx, keys...).Err()
}

// GetMulti 批量获取实体详情，返回命中字典与未命中代码切片 (基于 MGET 原生网络批处理)
func (c *EntityCache[T]) GetMulti(ctx context.Context, tid int64, codes []string) (map[string]T, []string, error) {
	targetCodes := lo.Uniq(lo.Compact(codes))
	if len(targetCodes) == 0 {
		return map[string]T{}, nil, nil
	}

	keys := lo.Map(targetCodes, func(code string, _ int) string {
		return c.Key(tid, code)
	})

	vals, err := c.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, nil, err
	}

	hitMap := make(map[string]T, len(targetCodes))
	missingCodes := make([]string, 0, len(targetCodes))

	for i, val := range vals {
		code := targetCodes[i]
		strVal, ok := val.(string)
		if !ok || strVal == "" {
			missingCodes = append(missingCodes, code)
			continue
		}

		var item T
		// 零拷贝转换直接传给反序列化器，避免堆上多余字节分配
		if err = c.serializer.Unmarshal(stringToBytes(strVal), &item); err != nil {
			missingCodes = append(missingCodes, code)
			continue
		}
		hitMap[code] = item
	}

	return hitMap, missingCodes, nil
}

// SetMulti 批量回写实体详情缓存 (基于 Pipeline 异步批量写入)
func (c *EntityCache[T]) SetMulti(ctx context.Context, tid int64, items []T) error {
	if len(items) == 0 {
		return nil
	}

	pipe := c.client.Pipeline()
	for _, item := range items {
		code := c.keyFn(item)
		if code == "" {
			continue
		}
		data, err := c.serializer.Marshal(item)
		if err != nil {
			continue
		}
		pipe.Set(ctx, c.Key(tid, code), data, c.JitterTTL())
	}
	_, err := pipe.Exec(ctx)
	return err
}

// stringToBytes 高性能零拷贝 string 转 []byte
func stringToBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/redis/go-redis/v9"
)

const (
	CAS_TICKET_PREFIX = "eiam:idp:cas:st:"
	DEFAULT_CAS_TTL   = 5 * time.Minute
)

// ErrCasTicketNotFound 票据不存在或已被消费核销 (防重放判定)
var ErrCasTicketNotFound = errors.New("cas ticket not found or already consumed")

// ICasCache CAS 票据生命周期缓存接口
type ICasCache interface {
	// SaveTicket 缓存 Service Ticket 会话数据
	SaveTicket(ctx context.Context, ticket string, data domain.CasTicketData, ttl time.Duration) error
	// GetAndDelTicket 原子获取并核销票据数据，彻底杜绝重放攻击
	GetAndDelTicket(ctx context.Context, ticket string) (domain.CasTicketData, error)
}

type casCache struct {
	client redis.Cmdable
}

// NewCasCache 构造 CAS 缓存实例
func NewCasCache(client redis.Cmdable) ICasCache {
	return &casCache{
		client: client,
	}
}

// SaveTicket 保存 CAS 票据并设置生存周期
func (c *casCache) SaveTicket(ctx context.Context, ticket string, data domain.CasTicketData, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = DEFAULT_CAS_TTL
	}
	bytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("序列化 CAS 票据失败: %w", err)
	}

	return c.client.Set(ctx, CAS_TICKET_PREFIX+ticket, bytes, ttl).Err()
}

// GetAndDelTicket 一次性核销票据并反序列化实体
// 依托 Redis 6.2+ 原生 GETDEL 实现原子读取并删除，从存储层彻底杜绝并发重放攻击
func (c *casCache) GetAndDelTicket(ctx context.Context, ticket string) (domain.CasTicketData, error) {
	var zero domain.CasTicketData

	bytes, err := c.client.GetDel(ctx, CAS_TICKET_PREFIX+ticket).Bytes()
	if errors.Is(err, redis.Nil) {
		return zero, ErrCasTicketNotFound
	}
	if err != nil {
		return zero, fmt.Errorf("获取并核销 CAS 票据异常: %w", err)
	}

	var data domain.CasTicketData
	if err = json.Unmarshal(bytes, &data); err != nil {
		return zero, fmt.Errorf("反序列化 CAS 票据失败: %w", err)
	}

	return data, nil
}

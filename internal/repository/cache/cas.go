package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	casTicketPrefix = "eiam:idp:cas:st:"
	defaultCasTTL   = 5 * time.Minute
)

// ErrCasTicketNotFound 票据不存在或已被核销
var ErrCasTicketNotFound = errors.New("cas ticket not found or already consumed")

// ICasCache CAS 票据生命周期缓存接口
type ICasCache interface {
	// SaveTicket 缓存 Service Ticket 会话数据
	SaveTicket(ctx context.Context, ticket string, data []byte, ttl time.Duration) error
	// GetAndDelTicket 原子获取并核销票据数据，彻底杜绝重放攻击
	GetAndDelTicket(ctx context.Context, ticket string) ([]byte, error)
}

type casCache struct {
	client redis.Cmdable
}

// NewCasCache 构造 CAS 缓存实现
func NewCasCache(client redis.Cmdable) ICasCache {
	return &casCache{
		client: client,
	}
}

func (c *casCache) SaveTicket(ctx context.Context, ticket string, data []byte, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = defaultCasTTL
	}
	key := fmt.Sprintf("%s%s", casTicketPrefix, ticket)
	return c.client.Set(ctx, key, data, ttl).Err()
}

func (c *casCache) GetAndDelTicket(ctx context.Context, ticket string) ([]byte, error) {
	key := fmt.Sprintf("%s%s", casTicketPrefix, ticket)
	// 使用 Redis 6.2+ 原生的 GETDEL 原子命令，若版本较旧则回退或由服务端执行
	val, err := c.client.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrCasTicketNotFound
	}
	if err != nil {
		return nil, err
	}
	return val, nil
}

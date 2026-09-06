package cache

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/redis/go-redis/v9"
)

// EmptyAPIID 标记未找到的接口，防止缓存穿透
const EmptyAPIID = -1

var (
	//go:embed lua/resource_invalidate_service.lua
	luaInvalidateService string
)

// IResourceCache 物理接口资源缓存
//go:generate mockgen -package=cachemocks -destination=./mocks/resource.mock.go github.com/Duke1616/eiam/internal/repository/cache IResourceCache
type IResourceCache interface {
	// GetAPI 获取接口缓存；未命中返回 ErrCacheNotFound
	GetAPI(ctx context.Context, service, method, path string) (domain.API, error)
	// SetAPI 缓存接口元数据，同时记录 key 到服务集合以支持按服务失效
	SetAPI(ctx context.Context, service, method, path string, api domain.API) error
	// SetEmptyAPI 缓存空对象哨兵以防缓存穿透
	SetEmptyAPI(ctx context.Context, service, method, path string) error
	// InvalidateServiceAPIs 清理指定微服务下的全部 API 缓存
	InvalidateServiceAPIs(ctx context.Context, service string) error
}

type resourceCache struct {
	client   redis.Cmdable
	apiTTL   time.Duration
	emptyTTL time.Duration
}

// NewResourceCache 创建资源缓存实例
func NewResourceCache(client redis.Cmdable) IResourceCache {
	return &resourceCache{
		client:   client,
		apiTTL:   2 * time.Hour,
		emptyTTL: 2 * time.Minute,
	}
}

func (c *resourceCache) apiKey(service, method, path string) string {
	return fmt.Sprintf("eiam:resource:api:%s:%s:%s", service, strings.ToUpper(method), path)
}

func (c *resourceCache) serviceKeysSet(service string) string {
	return fmt.Sprintf("eiam:resource:api_keys:%s", service)
}

func (c *resourceCache) GetAPI(ctx context.Context, service, method, path string) (domain.API, error) {
	key := c.apiKey(service, method, path)
	val, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return domain.API{}, ErrCacheNotFound
		}
		return domain.API{}, err
	}

	var api domain.API
	if err = json.Unmarshal(val, &api); err != nil {
		return domain.API{}, fmt.Errorf("反序列化 API 缓存失败: %w", err)
	}

	return api, nil
}

func (c *resourceCache) SetAPI(ctx context.Context, service, method, path string, api domain.API) error {
	data, err := json.Marshal(api)
	if err != nil {
		return fmt.Errorf("序列化 API 缓存失败: %w", err)
	}

	key := c.apiKey(service, method, path)
	setKey := c.serviceKeysSet(service)

	ttl := c.jitterTTL(c.apiTTL)

	pipe := c.client.Pipeline()
	pipe.Set(ctx, key, data, ttl)
	pipe.SAdd(ctx, setKey, key)
	pipe.Expire(ctx, setKey, ttl+time.Hour)
	_, err = pipe.Exec(ctx)
	return err
}

func (c *resourceCache) SetEmptyAPI(ctx context.Context, service, method, path string) error {
	emptyAPI := domain.API{
		ID:            EmptyAPIID,
		Service:       service,
		Method:        strings.ToUpper(method),
		Path:          path,
		FilterProfile: "",
	}

	data, err := json.Marshal(emptyAPI)
	if err != nil {
		return fmt.Errorf("序列化空 API 缓存失败: %w", err)
	}

	key := c.apiKey(service, method, path)
	setKey := c.serviceKeysSet(service)

	pipe := c.client.Pipeline()
	pipe.Set(ctx, key, data, c.emptyTTL)
	pipe.SAdd(ctx, setKey, key)
	pipe.Expire(ctx, setKey, c.emptyTTL+time.Hour)
	_, err = pipe.Exec(ctx)
	return err
}

func (c *resourceCache) InvalidateServiceAPIs(ctx context.Context, service string) error {
	setKey := c.serviceKeysSet(service)
	return c.client.Eval(ctx, luaInvalidateService, []string{setKey}).Err()
}

// jitterTTL 为过期时间增加 ±10% 随机抖动，打散失效时间窗口
func (c *resourceCache) jitterTTL(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	jitterRange := int64(base / 10)
	if jitterRange <= 0 {
		return base
	}
	jitter := time.Duration(rand.Int63n(jitterRange))
	if rand.Intn(2) == 0 {
		return base + jitter
	}
	return base - jitter
}

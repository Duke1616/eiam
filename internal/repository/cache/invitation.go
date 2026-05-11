package cache

import (
	"context"
	_ "embed"
	"fmt"
	"strconv"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/Duke1616/eiam/pkg/ctxutil"
	"github.com/redis/go-redis/v9"
)

var (
	//go:embed lua/invitation_incr.lua
	luaIncrUsedCountScript string
	luaIncrUsedCount       = redis.NewScript(luaIncrUsedCountScript)

	//go:embed lua/invitation_decr.lua
	luaDecrUsedCountScript string
	luaDecrUsedCount       = redis.NewScript(luaDecrUsedCountScript)
)

type IInvitationCache interface {
	// Set 设置邀请码活跃标识与初始化计数
	Set(ctx context.Context, inv domain.Invitation) error
	// Get 获取邀请码标识状态及实时计数
	Get(ctx context.Context, code string) (domain.Invitation, error)
	// IncrUsedCount 原子增加使用次数并检查上限（Lua 脚本实现）
	IncrUsedCount(ctx context.Context, code string, maxUses int) (int, error)
	// DecrUsedCount 原子减少使用次数（用于业务回滚）
	DecrUsedCount(ctx context.Context, code string) (int, error)
	// Delete 清理邀请码缓存数据
	Delete(ctx context.Context, code string) error
}

type invitationCache struct {
	client redis.Cmdable
}

func NewInvitationCache(client redis.Cmdable) IInvitationCache {
	return &invitationCache{client: client}
}

func (c *invitationCache) key(ctx context.Context, code string) string {
	tid := ctxutil.GetTenantID(ctx).Int64()
	return fmt.Sprintf("eiam:tenant:%d:invitation:%s:valid", tid, code)
}

func (c *invitationCache) countKey(ctx context.Context, code string) string {
	tid := ctxutil.GetTenantID(ctx).Int64()
	return fmt.Sprintf("eiam:tenant:%d:invitation:%s:count", tid, code)
}

func (c *invitationCache) Set(ctx context.Context, inv domain.Invitation) error {
	key := c.key(ctx, inv.Code)
	var expiration time.Duration
	if inv.ExpireAt > 0 {
		remaining := time.Until(time.UnixMilli(inv.ExpireAt))
		if remaining <= 0 {
			return nil
		}
		expiration = remaining
	} else {
		expiration = 30 * 24 * time.Hour
	}

	// 仅设置标识位，代表该邀请码在缓存有效期内
	_, err := c.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, key, "1", expiration)
		// 初始化计数器（如果不存在）
		pipe.SetNX(ctx, c.countKey(ctx, inv.Code), inv.UsedCount, expiration)
		return nil
	})
	return err
}

func (c *invitationCache) Get(ctx context.Context, code string) (domain.Invitation, error) {
	key := c.key(ctx, code)
	cntKey := c.countKey(ctx, code)

	// 获取标识位和实时计数
	cmds, err := c.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Get(ctx, key)
		pipe.Get(ctx, cntKey)
		return nil
	})

	if err != nil && err != redis.Nil {
		return domain.Invitation{}, err
	}

	// 检查标识位是否存在
	if _, err := cmds[0].(*redis.StringCmd).Result(); err != nil {
		return domain.Invitation{}, errs.ErrInvitationNotFound
	}

	var res domain.Invitation
	res.Code = code

	// 回填实时计数
	if cntStr, err := cmds[1].(*redis.StringCmd).Result(); err == nil {
		if count, err := strconv.Atoi(cntStr); err == nil {
			res.UsedCount = count
		}
	}

	return res, nil
}

func (c *invitationCache) IncrUsedCount(ctx context.Context, code string, maxUses int) (int, error) {
	res, err := luaIncrUsedCount.Run(ctx, c.client, []string{c.countKey(ctx, code), c.key(ctx, code)}, maxUses).Result()
	if err != nil {
		return 0, err
	}

	resStr, ok := res.(string)
	if !ok {
		return 0, fmt.Errorf("unexpected return type from lua: %T", res)
	}

	switch resStr {
	case "NOT_FOUND":
		return 0, errs.ErrInvitationNotFound
	case "FULL":
		return 0, errs.ErrInvitationFull
	default:
		return strconv.Atoi(resStr)
	}
}

func (c *invitationCache) DecrUsedCount(ctx context.Context, code string) (int, error) {
	res, err := luaDecrUsedCount.Run(ctx, c.client, []string{c.countKey(ctx, code), c.key(ctx, code)}).Result()
	if err != nil {
		return 0, err
	}

	resStr, ok := res.(string)
	if !ok {
		return 0, fmt.Errorf("unexpected return type from lua: %T", res)
	}

	return strconv.Atoi(resStr)
}

func (c *invitationCache) Delete(ctx context.Context, code string) error {
	_, err := c.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Del(ctx, c.key(ctx, code))
		pipe.Del(ctx, c.countKey(ctx, code))
		return nil
	})
	return err
}

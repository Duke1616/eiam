package cache

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Duke1616/eiam/internal/domain"
	"github.com/Duke1616/eiam/internal/errs"
	"github.com/redis/go-redis/v9"
)

var (
	luaIncrUsedCount = redis.NewScript(`
local count_key = KEYS[1]
local valid_key = KEYS[2]
local max_uses = tonumber(ARGV[1])

-- 1. 检查有效性
if redis.call("EXISTS", valid_key) == 0 then
    return -1
end

-- 2. 检查上限
if max_uses > 0 then
    local count = tonumber(redis.call("GET", count_key) or "0")
    if count >= max_uses then
        return -2
    end
end

-- 3. 增加计数
local new_count = redis.call("INCR", count_key)

-- 4. 如果达到上限，立即标记失效
if max_uses > 0 and new_count >= max_uses then
    redis.call("DEL", valid_key)
end

return new_count
`)
)

type IInvitationCache interface {
	// Set 设置邀请码活跃标识与初始化计数
	Set(ctx context.Context, inv domain.Invitation) error
	// Get 获取邀请码标识状态及实时计数
	Get(ctx context.Context, code string) (domain.Invitation, error)
	// IncrUsedCount 原子增加使用次数并检查上限（Lua 脚本实现）
	IncrUsedCount(ctx context.Context, code string, maxUses int) (int, error)
	// Delete 清理邀请码缓存数据
	Delete(ctx context.Context, tenantID int64, code string) error
}

type invitationCache struct {
	client redis.Cmdable
}

func NewInvitationCache(client redis.Cmdable) IInvitationCache {
	return &invitationCache{client: client}
}

func (c *invitationCache) key(code string) string {
	return fmt.Sprintf("eiam:invitation:%s:valid", code)
}

func (c *invitationCache) countKey(code string) string {
	return fmt.Sprintf("eiam:invitation:%s:count", code)
}

func (c *invitationCache) Set(ctx context.Context, inv domain.Invitation) error {
	key := c.key(inv.Code)
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
		pipe.SetNX(ctx, c.countKey(inv.Code), 0, expiration)
		return nil
	})
	return err
}

func (c *invitationCache) Get(ctx context.Context, code string) (domain.Invitation, error) {
	key := c.key(code)
	cntKey := c.countKey(code)

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
	val, err := luaIncrUsedCount.Run(ctx, c.client, []string{c.countKey(code), c.key(code)}, maxUses).Int()
	if err != nil {
		return 0, err
	}

	switch val {
	case -1:
		return 0, errs.ErrInvitationNotFound
	case -2:
		return 0, errs.ErrInvitationFull
	default:
		return val, nil
	}
}

func (c *invitationCache) Delete(ctx context.Context, tenantID int64, code string) error {
	_, err := c.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Del(ctx, c.key(code))
		pipe.Del(ctx, c.countKey(code))
		return nil
	})
	return err
}

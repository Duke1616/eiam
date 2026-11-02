package testioc

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
)

// InitRedis 初始化测试环境专属的 Redis 客户端
// 与生产 ioc.InitRedis 物理隔离，提供独立的健康探针、连接池与超时保障
func InitRedis() redis.Cmdable {
	type Config struct {
		Addr     string `mapstructure:"addr"`
		Password string `mapstructure:"password"`
		DB       int    `mapstructure:"db"`
	}

	var cfg Config
	if err := viper.UnmarshalKey("redis", &cfg); err != nil {
		panic(fmt.Errorf("无法解析测试环境 Redis 配置: %w", err))
	}

	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     20, // 满足测试并发测试套件的独立连接池
	})

	// 启动连通性探测 (Fail-Fast 防御)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		panic(fmt.Errorf("测试环境连接 Redis (%s) 失败: %w", cfg.Addr, err))
	}

	return client
}

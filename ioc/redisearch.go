package ioc

import (
	"fmt"
	"strings"

	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/RediSearch/redisearch-go/v2/redisearch"
	"github.com/gomodule/redigo/redis"
	"github.com/spf13/viper"
)

func InitRedisSearch() *redisearch.Client {
	type Config struct {
		Addr     string `mapstructure:"addr"`
		Password string `mapstructure:"password"`
		DB       int    `mapstructure:"db"`
	}

	var cfg Config
	if err := viper.UnmarshalKey("redis", &cfg); err != nil {
		panic(fmt.Errorf("unable to decode into structure: %v", err))
	}

	// RediSearch 引擎有官方硬性约束：所有 FT.* 索引必须且只能创建在 DB 0 上（Cannot create index on db != 0）。
	// 因此此处连接池强制路由到 DB 0，避免全局配置中 db != 0 导致服务崩溃。
	pool := &redis.Pool{Dial: func() (redis.Conn, error) {
		return redis.Dial("tcp", cfg.Addr,
			redis.DialPassword(cfg.Password),
			redis.DialDatabase(0))
	}}

	client := redisearch.NewClientFromPool(pool, cache.LdapUserIndexName)

	// 统一维护 Schema：直接引用 cache 模块导出的 Schema 定义，确保单一信任源
	sc := cache.NewLdapUserSchema()

	// 幂等初始化：直接尝试创建索引，若已存在则忽略，其他错误 panic 快速失败。
	// 不依赖 Info() 的间接判断，避免"Info 成功但索引已丢失"的窗口期误判。
	indexDefinition := redisearch.NewIndexDefinition().AddPrefix(cache.LdapUserKeyPrefix)
	if err := client.CreateIndexWithIndexDefinition(sc, indexDefinition); err != nil {
		if !strings.Contains(err.Error(), "Index already exists") {
			panic(fmt.Errorf("RediSearch 索引 %q 初始化失败，请检查 Redis Stack 是否已加载 RediSearch 模块: %w",
				cache.LdapUserIndexName, err))
		}
	}

	return client
}

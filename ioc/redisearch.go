package ioc

import (
	"fmt"

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

	pool := &redis.Pool{Dial: func() (redis.Conn, error) {
		return redis.Dial("tcp", cfg.Addr,
			redis.DialPassword(cfg.Password),
			redis.DialDatabase(cfg.DB))
	}}

	client := redisearch.NewClientFromPool(pool, cache.LdapUserIndexName)

	// 统一维护 Schema
	sc := redisearch.NewSchema(redisearch.DefaultOptions).
		AddField(redisearch.NewTextField("tid")).
		AddField(redisearch.NewTextField("username")).
		AddField(redisearch.NewTextField("display_name")).
		AddField(redisearch.NewTextField("title")).
		AddField(redisearch.NewTextField("email")).
		AddField(redisearch.NewNumericField("updated_at"))

	// 自动初始化：如果索引不存在则创建
	_, err := client.Info()
	if err != nil {
		indexDefinition := redisearch.NewIndexDefinition().AddPrefix(cache.LdapUserKeyPrefix)
		_ = client.CreateIndexWithIndexDefinition(sc, indexDefinition)
	}

	return client
}

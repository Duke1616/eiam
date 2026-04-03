package ioc

import (
	"fmt"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	defaultrolemanager "github.com/casbin/casbin/v2/rbac/default-role-manager"
	gormAdapter "github.com/casbin/gorm-adapter/v3"
	redisWatcher "github.com/casbin/redis-watcher/v2"
	_ "github.com/go-sql-driver/mysql"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

const (
	rbacModel = `[request_definition]
r = sub, obj

[policy_definition]
p = sub, obj

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj`
)

func InitCasbin(db *gorm.DB) *casbin.SyncedEnforcer {
	adapter, err := gormAdapter.NewAdapterByDB(db)
	if err != nil {
		fmt.Printf("警告: 初始化 Casbin Adapter 失败: %v\n", err)
		return nil
	}

	m, err := model.NewModelFromString(rbacModel)
	if err != nil {
		fmt.Printf("警告: Casbin 模型解析失败: %v\n", err)
		return nil
	}

	type RedisConfig struct {
		Addr     string `mapstructure:"addr"`
		DB       int    `mapstructure:"db"`
		UserName string `mapstructure:"username"`
		Password string `mapstructure:"password"`
	}
	var cfg RedisConfig
	if err = viper.UnmarshalKey("casbin.redis", &cfg); err != nil {
		fmt.Printf("警告: 无法读取 Redis 配置: %v\n", err)
	}

	w, err := redisWatcher.NewWatcher(cfg.Addr, redisWatcher.WatcherOptions{
		Options: redis.Options{
			DB:       cfg.DB,
			Password: cfg.Password,
		},
		Channel: "/casbin",
	})
	if err != nil {
		panic(err)
	}

	enforcer, err := casbin.NewSyncedEnforcer(m, adapter)
	if err != nil {
		fmt.Printf("警告: Enforcer 初始化失败: %v\n", err)
		return nil
	}

	_ = enforcer.SetWatcher(w)
	_ = w.SetUpdateCallback(updateCallback)

	enforcer.EnableLog(false)
	if err = enforcer.LoadPolicy(); err != nil {
		panic(err)
	}

	enforcer.StartAutoLoadPolicy(time.Minute)

	// 核心配置 —— 全局域穿透逻辑
	// 当我们在某个租户 TID 下查找角色关系时，如果规则是定义在全局域 "0" 下的，
	// 通过下述匹配函数，Casbin 会自动将 TID 匹配到 "0"，从而实现全局继承关系的自动解析。
	enforcer.GetRoleManager().(*defaultrolemanager.RoleManager).AddDomainMatchingFunc("DomainMatch", func(d1, d2 string) bool {
		return d1 == d2 || d2 == "0"
	})

	return enforcer
}

func updateCallback(rev string) {
	// 可选打印 rev
}

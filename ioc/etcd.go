package ioc

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// InitEtcd 初始化 Etcd 客户端组件
func InitEtcd() *clientv3.Client {
	var cfg clientv3.Config

	if err := viper.UnmarshalKey("etcd", &cfg); err != nil {
		panic(fmt.Errorf("unable to decode into struct: %v", err))
	}

	client, err := clientv3.New(clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		panic(err)
	}
	return client
}

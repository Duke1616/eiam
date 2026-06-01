package ioc

import (
	"github.com/Duke1616/eiam/pkg/web/capability"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func InitCapabilityRegistry(client *clientv3.Client) capability.Registry {
	// SDK 的 Registry 默认使用 Etcd 模式，TTL 60s
	return capability.NewEtcdRegistry(client, 60)
}

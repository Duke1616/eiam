package ioc

import (
	"github.com/Duke1616/eiam/pkg/web/capability"
	synceretcd "github.com/Duke1616/eiam/pkg/web/capability/syncer/etcd"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func InitCapabilityRegistry(client *clientv3.Client) capability.Registry {
	// SDK 的 Registry 默认使用 Etcd 模式，TTL 60s
	return synceretcd.New(client, 60)
}


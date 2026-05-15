package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gotomicro/ego/core/elog"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

const (
	manifestPrefix = "/eiam/manifests"
	lockPrefix     = "/eiam/locks"
)

type etcdRegistry struct {
	client *clientv3.Client
	ttl    int
	l      *elog.Component
}

// NewEtcdRegistry 构建一个高可用的资产注册器
func NewEtcdRegistry(client *clientv3.Client, ttl int) Registry {
	if ttl <= 0 {
		ttl = 60
	}
	return &etcdRegistry{
		client: client,
		ttl:    ttl,
		l:      elog.DefaultLogger,
	}
}

// Sync 执行资产同步
// 在分布式环境下，该方法会启动一个后台 Leader 选举任务，确保集群中只有一个实例在报备资产
func (r *etcdRegistry) Sync(ctx context.Context, req SyncRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("EIAM SDK 协议序列化失败: %w", err)
	}

	// 启动后台注册控制器
	go r.runRegistrationController(ctx, req.Service, data)

	return nil
}

// runRegistrationController 抢占式注册控制器
func (r *etcdRegistry) runRegistrationController(ctx context.Context, service string, data []byte) {
	manifestKey := fmt.Sprintf("%s/%s", manifestPrefix, service)
	lockKey := fmt.Sprintf("%s/%s", lockPrefix, service)

	for {
		select {
		case <-ctx.Done():
			r.l.Info("EIAM SDK 资产注册控制器已停止", elog.String("service", service))
			return
		default:
			if err := r.executeLeaderRegistration(ctx, manifestKey, lockKey, data); err != nil {
				r.l.Error("EIAM SDK 注册控制器执行异常，准备重试",
					elog.String("service", service),
					elog.FieldErr(err))
				// 异常退避，防止 Etcd 抖动导致 CPU 暴涨
				time.Sleep(10 * time.Second)
			}
		}
	}
}

// executeLeaderRegistration 执行单次 Leader 选举与资产报备
func (r *etcdRegistry) executeLeaderRegistration(ctx context.Context, manifestKey, lockKey string, data []byte) error {
	// 1. 建立会话
	sess, err := concurrency.NewSession(r.client, concurrency.WithTTL(r.ttl))
	if err != nil {
		return err
	}
	defer sess.Close()

	// 2. 竞争 Leader 锁
	mutex := concurrency.NewMutex(sess, lockKey)
	r.l.Info("EIAM SDK 正在尝试竞争资产报备 Leader 身份...", elog.String("lock", lockKey))

	if err = mutex.Lock(ctx); err != nil {
		return err
	}
	defer mutex.Unlock(context.Background())

	// 3. 报备资产清单
	_, err = r.client.Put(ctx, manifestKey, string(data), clientv3.WithLease(sess.Lease()))
	if err != nil {
		return err
	}

	r.l.Info("EIAM SDK 抢占 Leader 成功，已完成资产同步",
		elog.String("service", manifestKey),
		elog.Int64("lease", int64(sess.Lease())))

	// 4. 维持状态直到会话结束
	select {
	case <-ctx.Done():
		return nil
	case <-sess.Done():
		r.l.Warn("EIAM SDK Etcd 会话已断开，重新触发选举")
		return nil
	}
}

package etcd

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/gotomicro/ego/core/elog"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

const (
	manifestPrefix = "/eiam/manifests"
	hashPrefix     = "/eiam/hashes"
)

type etcdRegistry struct {
	client      *clientv3.Client
	ttl         int
	l           *elog.Component
	controllers sync.Map
}

type registrationController struct {
	req    capability.SyncRequest
	cancel context.CancelFunc
	mu     sync.RWMutex
}

// New 构建一个基于 Etcd 的资产注册器
func New(client *clientv3.Client, ttl int) capability.Reporter {
	if ttl <= 0 {
		ttl = 60
	}
	return &etcdRegistry{
		client: client,
		ttl:    ttl,
		l:      elog.DefaultLogger,
	}
}

func (r *etcdRegistry) Sync(ctx context.Context, req capability.SyncRequest) error {
	ownerKey := req.OwnerKey()
	service := req.Service

	actual, loaded := r.controllers.LoadOrStore(ownerKey, &registrationController{
		req: req,
	})
	ctrl := actual.(*registrationController)

	if loaded {
		ctrl.mu.Lock()
		oldHash := (&ctrl.req).Hash()
		newHash := (&req).Hash()

		if oldHash == newHash {
			ctrl.mu.Unlock()
			return nil
		}
		ctrl.req = req
		if ctrl.cancel != nil {
			ctrl.cancel()
			ctrl.cancel = nil
		}
		ctrl.mu.Unlock()
	}

	subCtx, cancel := context.WithCancel(context.Background())
	ctrl.mu.Lock()
	ctrl.cancel = cancel
	ctrl.mu.Unlock()

	go r.startLifecycleLoop(subCtx, ctrl, service, ownerKey)
	return nil
}

func (r *etcdRegistry) startLifecycleLoop(ctx context.Context, ctrl *registrationController, service, ownerKey string) {
	manifestKey := fmt.Sprintf("%s/%s", manifestPrefix, ownerKey)
	hashKey := fmt.Sprintf("%s/%s", hashPrefix, ownerKey)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		session, err := concurrency.NewSession(r.client, concurrency.WithTTL(r.ttl))
		if err != nil {
			r.l.Error("创建 Etcd 会话失败，稍后重试", elog.FieldErr(err), elog.String("ownerKey", ownerKey))
			time.Sleep(5 * time.Second)
			continue
		}

		ctrl.mu.RLock()
		currentReq := ctrl.req
		ctrl.mu.RUnlock()

		currentHash := (&currentReq).Hash()
		content, err := json.Marshal(currentReq)
		if err != nil {
			r.l.Error("序列化资产快照失败", elog.FieldErr(err))
			session.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		resp, err := r.client.Get(ctx, hashKey)
		needUpdateManifest := true
		if err == nil && len(resp.Kvs) > 0 {
			if string(resp.Kvs[0].Value) == currentHash {
				needUpdateManifest = false
			}
		}

		if needUpdateManifest {
			_, err = r.client.Txn(ctx).
				Then(
					clientv3.OpPut(manifestKey, string(content), clientv3.WithLease(session.Lease())),
					clientv3.OpPut(hashKey, currentHash),
				).Commit()
		} else {
			_, err = r.client.Put(ctx, manifestKey, string(content), clientv3.WithLease(session.Lease()))
		}

		if err != nil {
			r.l.Error("注册资产到 Etcd 失败", elog.FieldErr(err), elog.String("ownerKey", ownerKey))
			session.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		r.l.Info("成功注册资产到 Etcd",
			elog.String("service", service),
			elog.String("ownerKey", ownerKey),
			elog.String("hash", currentHash),
			elog.Any("updated", needUpdateManifest),
		)

		select {
		case <-ctx.Done():
			session.Close()
			return
		case <-session.Done():
			r.l.Warn("Etcd 租约会话过期，重新建立", elog.String("ownerKey", ownerKey))
		}
	}
}

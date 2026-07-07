package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"sync"

	"github.com/gotomicro/ego/core/elog"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

const (
	manifestPrefix = "/eiam/manifests"
	hashPrefix     = "/eiam/hashes" // 永久存储的资产哈希
)

type etcdRegistry struct {
	client      *clientv3.Client
	ttl         int
	l           *elog.Component
	controllers sync.Map
}

type registrationController struct {
	req    SyncRequest
	cancel context.CancelFunc
	mu     sync.RWMutex
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

func (r *etcdRegistry) Sync(ctx context.Context, req SyncRequest) error {
	ownerKey := req.OwnerKey()
	service := req.Service

	// 1. 检查该服务是否已有运行中的控制器
	actual, loaded := r.controllers.LoadOrStore(ownerKey, &registrationController{
		req: req,
	})
	ctrl := actual.(*registrationController)

	if loaded {
		// 2. 如果已存在，更新数据并比较哈希值
		ctrl.mu.Lock()
		oldHash := (&ctrl.req).Hash()
		newHash := (&req).Hash()
		ctrl.req = req
		ctrl.mu.Unlock()

		// 如果资产哈希发生变化（说明有新的权限、API或 code 码变更），
		// 此时旧的控制器很有可能正挂起在 Leader 维持的 select 中（executeLeaderRegistration 第五步）而无法感知。
		// 我们必须主动 cancel 终止旧控制器，并为该服务建立并启动全新的控制器，以秒级执行对账。
		if oldHash != newHash {
			r.l.Info("EIAM SDK 检测到运行中服务的资产哈希变更，正在重构控制器协程...",
				elog.String("service", service),
				elog.String("source", req.Source),
				elog.String("oldHash", oldHash),
				elog.String("newHash", newHash))

			if ctrl.cancel != nil {
				ctrl.cancel()
			}

			// 重新构建一个全新的控制器实例
			cCtx, cancel := context.WithCancel(context.Background())
			newCtrl := &registrationController{
				req:    req,
				cancel: cancel,
			}
			r.controllers.Store(ownerKey, newCtrl)

			// 异步启动全新的注册控制器以秒级重新竞选 Leader 并执行全量对账
			go r.runRegistrationController(cCtx, newCtrl)
		}
		return nil
	}

	// 3. 如果是首次同步，启动后台控制器
	cCtx, cancel := context.WithCancel(context.Background())
	ctrl.cancel = cancel

	go r.runRegistrationController(cCtx, ctrl)

	return nil
}

// runRegistrationController 抢占式注册控制器
func (r *etcdRegistry) runRegistrationController(ctx context.Context, ctrl *registrationController) {
	service := ctrl.req.Service
	ownerKey := ctrl.req.OwnerKey()
	manifestKey := fmt.Sprintf("%s/%s", manifestPrefix, ownerKey)
	hashKey := fmt.Sprintf("%s/%s", hashPrefix, ownerKey)

	for {
		select {
		case <-ctx.Done():
			r.l.Info("EIAM SDK 资产注册控制器已停止", elog.String("service", service), elog.String("source", ctrl.req.Source))
			return
		default:
			// 获取当前最新的请求数据
			ctrl.mu.RLock()
			req := ctrl.req
			ctrl.mu.RUnlock()

			if err := r.executeLeaderRegistration(ctx, req, manifestKey, hashKey); err != nil {
				r.l.Error("EIAM SDK 注册控制器执行异常，准备重试",
					elog.String("service", service),
					elog.String("source", req.Source),
					elog.FieldErr(err))
				time.Sleep(10 * time.Second)
			}
		}
	}
}

// executeLeaderRegistration 执行单次 Leader 选举与资产报备
func (r *etcdRegistry) executeLeaderRegistration(ctx context.Context, req SyncRequest, manifestKey, hashKey string) error {
	currentHash := req.Hash()

	// 1. 乐观预检：如果 Hash 一致且在线清单已存在，则本节点无需抢锁，进入观察模式
	resp, err := r.client.Get(ctx, hashKey)
	if err == nil && len(resp.Kvs) > 0 && string(resp.Kvs[0].Value) == currentHash {
		mResp, _ := r.client.Get(ctx, manifestKey)
		if len(mResp.Kvs) > 0 {
			r.l.Info("EIAM SDK 资产版本一致且集群已有 Leader，本节点进入 Standby 模式", elog.String("service", req.Service), elog.String("source", req.Source))
			// 观察者模式：等待 1 分钟后再检查，或者监听事件（这里简单处理为 Sleep）
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Minute):
				return nil
			}
		}
	}

	// 2. 准备会话
	sess, err := concurrency.NewSession(r.client, concurrency.WithTTL(r.ttl))
	if err != nil {
		return err
	}
	defer sess.Close()

	// 3. 竞争 Leader 身份
	mutex := concurrency.NewMutex(sess, manifestKey)
	r.l.Info("EIAM SDK 正在尝试竞争资产报备 Leader 身份...", elog.String("service", req.Service), elog.String("source", req.Source))

	if err = mutex.Lock(ctx); err != nil {
		return err
	}
	defer mutex.Unlock(context.Background())

	// 4. 二次检查与同步 (双重检查锁模式)
	// 拿到锁后再次确认 Hash，决定是执行“全量对账”还是仅仅“接管心跳”
	dbHashResp, _ := r.client.Get(ctx, hashKey)
	shouldSync := len(dbHashResp.Kvs) == 0 || string(dbHashResp.Kvs[0].Value) != currentHash

	data, _ := json.Marshal(req)
	if shouldSync {
		r.l.Info("EIAM SDK 发现资产版本变更，启动全量对账...", elog.String("service", req.Service), elog.String("source", req.Source), elog.String("hash", currentHash))
		// 这里由于 Registry 接口定义限制，暂无法直接调用外部对账 API，
		// 但我们可以在这里把全量数据写入 manifestKey，触发 EIAM Server 的 Watcher
		if _, err = r.client.Put(ctx, manifestKey, string(data), clientv3.WithLease(sess.Lease())); err != nil {
			return err
		}
		// 同步成功后更新永久存根
		_, _ = r.client.Put(ctx, hashKey, currentHash)
		r.l.Info("EIAM SDK 资产全量同步指令已下发", elog.String("service", req.Service), elog.String("source", req.Source))
	} else {
		// 仅接管心跳，维持在线状态
		r.l.Info("EIAM SDK 接管 Leader 成功，资产版本有效，仅维持心跳", elog.String("service", req.Service), elog.String("source", req.Source))
		if _, err = r.client.Put(ctx, manifestKey, string(data), clientv3.WithLease(sess.Lease())); err != nil {
			return err
		}
	}

	// 5. 维持 Leader 状态直到生命周期结束
	select {
	case <-ctx.Done():
		return nil
	case <-sess.Done():
		r.l.Warn("EIAM SDK Etcd 会话断开，准备重新选举", elog.String("service", req.Service), elog.String("source", req.Source))
		return nil
	}
}

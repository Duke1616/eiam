package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Duke1616/eiam/internal/service/resource"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/gotomicro/ego/core/elog"
	"github.com/meoying/dlock-go"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	workerLockKey  = "eiam_discovery_worker_lock"
	manifestPath   = "/eiam/manifests/"
	lockExpiration = 30 * time.Second
)

// Worker 资产发现调度器，负责监听 Etcd 状态并驱动对账引擎
type Worker struct {
	client     *clientv3.Client
	reconciler resource.Reconciler
	init       resource.IInitializer
	l          *elog.Component
	dClient    dlock.Client
}

// NewWorker 构建一个新的调度器实例
func NewWorker(client *clientv3.Client, reconciler resource.Reconciler, init resource.IInitializer, dClient dlock.Client) *Worker {
	return &Worker{
		client:     client,
		reconciler: reconciler,
		init:       init,
		dClient:    dClient,
		l:          elog.DefaultLogger,
	}
}

// Start 开启监听与调度任务 (实现 ioc.Task 接口)
func (w *Worker) Start(ctx context.Context) {
	go w.runLockedLoop(ctx)
}

// runLockedLoop 带有分布式锁保护的主循环
func (w *Worker) runLockedLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err := w.tryExecuteTask(ctx); err != nil {
				w.l.Warn("Discovery Worker 运行异常，正在退避重试", elog.FieldErr(err))
				time.Sleep(5 * time.Second)
			} else {
				// 正常结束（可能是抢不到锁或 Job 正常停止），睡一会儿再试，防止 CPU 轮询过快
				time.Sleep(10 * time.Second)
			}
		}
	}
}

// tryExecuteTask 尝试抢占锁并执行具体的监听对账任务
func (w *Worker) tryExecuteTask(ctx context.Context) error {
	// 1. 初始化并抢占分布式锁
	lock, err := w.dClient.NewLock(ctx, workerLockKey, lockExpiration)
	if err != nil {
		return err
	}

	if err = lock.Lock(ctx); err != nil {
		// NOTE: 如果锁被人持有，说明集群中已有 Leader，当前实例切换为 Standby 模式，不作为异常处理
		if strings.Contains(err.Error(), "锁被人持有") {
			w.l.Info("资产对账锁已被占用，当前实例处于待命状态 (Standby)")
			return nil
		}
		return err
	}
	defer func() {
		_ = lock.Unlock(context.Background())
	}()

	w.l.Info("成功抢占分布式锁，对账调度器进入工作状态")

	// 2. 执行核心对账工作 (该方法是阻塞的)
	return w.runReconcileJob(ctx)
}

// runReconcileJob 核心对账监听逻辑
func (w *Worker) runReconcileJob(ctx context.Context) error {
	// 0. 执行内置静态资产同步 (Pipeline 模式)
	w.init.NewPipeline(ctx).
		Step("同步内置服务", w.init.SyncServices).
		Step("同步内置菜单", w.init.SyncMenus).
		Run()

	// 1. 冷启动快照全量扫描
	if err := w.scanInitialManifests(ctx); err != nil {
		w.l.Error("全量快照扫描失败", elog.FieldErr(err))
	}

	// 2. 启动增量监听
	watchCh := w.client.Watch(ctx, manifestPath, clientv3.WithPrefix())
	w.l.Info("资产调度器已就绪，正在监听微服务变动...")

	for {
		select {
		case <-ctx.Done():
			return nil
		case watchResp, ok := <-watchCh:
			if !ok {
				return fmt.Errorf("etcd watch channel closed")
			}
			w.handleWatchEvents(ctx, watchResp.Events)
		}
	}
}

func (w *Worker) scanInitialManifests(ctx context.Context) error {
	resp, err := w.client.Get(ctx, manifestPath, clientv3.WithPrefix())
	if err != nil {
		return err
	}
	for _, kv := range resp.Kvs {
		w.process(ctx, kv.Value)
	}
	return nil
}

func (w *Worker) handleWatchEvents(ctx context.Context, events []*clientv3.Event) {
	for _, event := range events {
		switch event.Type {
		case clientv3.EventTypePut:
			w.process(ctx, event.Kv.Value)
		case clientv3.EventTypeDelete:
			w.l.Info("检测到服务资产离线", elog.String("key", string(event.Kv.Key)))
		}
	}
}

// process 解析快照并驱动对账引擎执行同步
func (w *Worker) process(ctx context.Context, data []byte) {
	var req capability.SyncRequest
	if err := json.Unmarshal(data, &req); err != nil {
		w.l.Error("解析资产协议失败", elog.FieldErr(err))
		return
	}

	if err := w.reconciler.Reconcile(ctx, req); err != nil {
		w.l.Error("驱动资产对账失败",
			elog.String("service", req.Service),
			elog.FieldErr(err))
	}
}

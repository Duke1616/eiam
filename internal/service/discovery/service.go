package discovery

import (
	"context"
	"fmt"

	"github.com/Duke1616/eiam/internal/repository/cache"
	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/google/uuid"
	"github.com/gotomicro/ego/core/elog"
)

// IDiscoveryService 资产发现业务编排服务
type IDiscoveryService interface {
	// Sync 接收微服务资产上报请求，执行分布式短路判定、防并发互斥与资产入库
	Sync(ctx context.Context, req capability.SyncRequest) (isNew bool, err error)
}

type discoveryService struct {
	registry capability.Registry
	cache    cache.IDiscoveryCache
	logger   *elog.Component
}

// NewDiscoveryService 构建资产发现业务服务
func NewDiscoveryService(
	registry capability.Registry,
	cache cache.IDiscoveryCache,
) IDiscoveryService {
	return &discoveryService{
		registry: registry,
		cache:    cache,
		logger:   elog.DefaultLogger.With(elog.FieldComponent("discovery-service")),
	}
}

// Sync 执行分布式资产同步业务编排：
// 1. 跨节点分布式 Hash 缓存比对：多节点全局共享，命中则秒级短路；
// 2. 分布式并发控制：同服务多 Pod 同时启动时，通过带 owner 的分布式锁防止数据库死锁与并发写入风暴；
// 3. 驱动底层 Registry 录入引擎并刷新分布式 Hash。
func (s *discoveryService) Sync(ctx context.Context, req capability.SyncRequest) (bool, error) {
	currentHash := req.Hash()

	// 1. 跨节点分布式 Hash 缓存比对
	lastHash, err := s.cache.GetLastHash(ctx, req.Service)
	if err == nil && lastHash != "" && lastHash == currentHash {
		// 资产未变动，秒级短路放行
		return false, nil
	}

	// 2. 分布式防并发互斥锁（采用随机 owner 标识，防超时后误删其他实例的锁）
	lockOwner := uuid.New().String()
	acquired, err := s.cache.TryLockSync(ctx, req.Service, lockOwner, 0)
	if err == nil && !acquired {
		// 说明同一服务的其他 Pod 实例正在执行对账入库，当前实例无需重复发起
		s.logger.Info("微服务资产正在并发对账中，跳过重复写入", elog.String("service", req.Service))
		return false, nil
	}
	if acquired {
		defer func() {
			_ = s.cache.UnlockSync(context.Background(), req.Service, lockOwner)
		}()
	}

	// 3. 异步驱动 Registry 统一录入引擎（长任务使用独立 context）
	if err = s.registry.Sync(context.Background(), req); err != nil {
		return false, fmt.Errorf("微服务资产同步落库失败: %w", err)
	}

	// 4. 对账成功后，将最新的 Hash 刷入分布式 Redis 缓存
	_ = s.cache.SetLastHash(context.Background(), req.Service, currentHash)

	return true, nil
}

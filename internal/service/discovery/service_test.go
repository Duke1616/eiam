package discovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Duke1616/eiam/pkg/web/capability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockDiscoveryCache struct {
	hashes map[string]string
	locked map[string]bool
}

func newMockDiscoveryCache() *mockDiscoveryCache {
	return &mockDiscoveryCache{
		hashes: make(map[string]string),
		locked: make(map[string]bool),
	}
}

func (m *mockDiscoveryCache) GetLastHash(ctx context.Context, service string) (string, error) {
	return m.hashes[service], nil
}

func (m *mockDiscoveryCache) SetLastHash(ctx context.Context, service, hash string) error {
	m.hashes[service] = hash
	return nil
}

func (m *mockDiscoveryCache) TryLockSync(ctx context.Context, service, owner string, expiration time.Duration) (bool, error) {
	if m.locked[service] {
		return false, nil
	}
	m.locked[service] = true
	return true, nil
}

func (m *mockDiscoveryCache) UnlockSync(ctx context.Context, service, owner string) error {
	delete(m.locked, service)
	return nil
}

type mockCapabilityRegistry struct {
	syncCount int
	shouldErr bool
}

func (m *mockCapabilityRegistry) Sync(ctx context.Context, req capability.SyncRequest) error {
	if m.shouldErr {
		return errors.New("sync db error")
	}
	m.syncCount++
	return nil
}

func TestDiscoveryService_Sync(t *testing.T) {
	t.Run("首次同步：获取锁并成功对账入库，刷入分布式 Hash", func(t *testing.T) {
		mockCache := newMockDiscoveryCache()
		mockReg := &mockCapabilityRegistry{}
		svc := NewDiscoveryService(mockReg, mockCache)

		req := capability.SyncRequest{
			Service: "ecmdb",
			Permissions: []capability.Permission{
				{Service: "ecmdb", Code: "ecmdb:host:view", Name: "查看主机"},
			},
		}

		isNew, err := svc.Sync(context.Background(), req)
		require.NoError(t, err)
		assert.True(t, isNew)
		assert.Equal(t, 1, mockReg.syncCount)

		// 验证 Redis 中存储了最新的 Hash
		val, _ := mockCache.GetLastHash(context.Background(), "ecmdb")
		assert.Equal(t, req.Hash(), val)
		// 锁应已被释放
		assert.False(t, mockCache.locked["ecmdb"])
	})

	t.Run("重复相同 Hash 同步：命中分布式缓存秒级短路，不重复调用对账入库", func(t *testing.T) {
		mockCache := newMockDiscoveryCache()
		mockReg := &mockCapabilityRegistry{}
		svc := NewDiscoveryService(mockReg, mockCache)

		req := capability.SyncRequest{
			Service: "ecmdb",
			Permissions: []capability.Permission{
				{Service: "ecmdb", Code: "ecmdb:host:view", Name: "查看主机"},
			},
		}

		// 预先存入该 Hash
		_ = mockCache.SetLastHash(context.Background(), "ecmdb", req.Hash())

		isNew, err := svc.Sync(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, isNew)
		// 未调用底层 Registry.Sync
		assert.Equal(t, 0, mockReg.syncCount)
	})

	t.Run("并发调用未抢到锁：优雅跳过不产生重复对账", func(t *testing.T) {
		mockCache := newMockDiscoveryCache()
		mockReg := &mockCapabilityRegistry{}
		svc := NewDiscoveryService(mockReg, mockCache)

		// 模拟已有锁被占用
		mockCache.locked["ecmdb"] = true

		req := capability.SyncRequest{
			Service: "ecmdb",
			Permissions: []capability.Permission{
				{Service: "ecmdb", Code: "ecmdb:host:edit", Name: "修改主机"},
			},
		}

		isNew, err := svc.Sync(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, isNew)
		// 并发未抢到锁，直接返回，未调用底层对账
		assert.Equal(t, 0, mockReg.syncCount)
	})
}

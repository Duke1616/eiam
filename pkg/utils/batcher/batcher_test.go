package batcher

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBatcher_SizeTrigger(t *testing.T) {
	var (
		mu      sync.Mutex
		batches [][]int
	)

	b := NewBatcher[int](
		func(ctx context.Context, batch []int) error {
			mu.Lock()
			defer mu.Unlock()
			cp := make([]int, len(batch))
			copy(cp, batch)
			batches = append(batches, cp)
			return nil
		},
		WithBatchSize[int](3),
		WithFlushInterval[int](10*time.Second), // 设置长间隔，确保由定量触发
	)
	defer b.Close()

	for i := 1; i <= 6; i++ {
		assert.True(t, b.Push(i))
	}

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 2, len(batches))
	assert.Equal(t, []int{1, 2, 3}, batches[0])
	assert.Equal(t, []int{4, 5, 6}, batches[1])
}

func TestBatcher_IntervalTrigger(t *testing.T) {
	var (
		mu      sync.Mutex
		batches [][]int
	)

	b := NewBatcher[int](
		func(ctx context.Context, batch []int) error {
			mu.Lock()
			defer mu.Unlock()
			cp := make([]int, len(batch))
			copy(cp, batch)
			batches = append(batches, cp)
			return nil
		},
		WithBatchSize[int](100),
		WithFlushInterval[int](30*time.Millisecond),
	)
	defer b.Close()

	assert.True(t, b.Push(10))
	assert.True(t, b.Push(20))

	time.Sleep(80 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, len(batches))
	assert.Equal(t, []int{10, 20}, batches[0])
}

func TestBatcher_DropProtection(t *testing.T) {
	// 容量为 2 的极小队列，模拟下游完全卡死时的非阻塞丢弃保护
	b := NewBatcher[int](
		func(ctx context.Context, batch []int) error {
			time.Sleep(500 * time.Millisecond)
			return nil
		},
		WithBatchSize[int](10),
		WithBufferCap[int](2),
		WithFlushInterval[int](time.Second),
	)
	defer b.Close()

	// 快速灌入大量数据
	for i := 0; i < 50; i++ {
		b.Push(i)
	}

	assert.Greater(t, b.DroppedCount(), uint64(0))
}

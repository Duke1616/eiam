package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testEntity struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

func TestEntityCache_Key(t *testing.T) {
	cache := NewEntityCache[testEntity](
		nil,
		"test:detail",
		10*time.Minute,
		func(e testEntity) string { return e.Code },
	)

	key := cache.Key(100, "sample_code")
	assert.Equal(t, "eiam:test:detail:100:sample_code", key)
}

func TestEntityCache_JitterTTL(t *testing.T) {
	baseTTL := 30 * time.Minute
	cache := NewEntityCache[testEntity](
		nil,
		"test:detail",
		baseTTL,
		func(e testEntity) string { return e.Code },
	)

	// 验证抖动范围严格在 ±10% 以内 (即 27m ~ 33m)
	minTTL := 27 * time.Minute
	maxTTL := 33 * time.Minute

	for i := 0; i < 100; i++ {
		jittered := cache.JitterTTL()
		assert.GreaterOrEqual(t, jittered, minTTL)
		assert.LessOrEqual(t, jittered, maxTTL)
	}
}

func TestEntityCache_EmptyInputs(t *testing.T) {
	cache := NewEntityCache[testEntity](
		nil,
		"test:detail",
		10*time.Minute,
		func(e testEntity) string { return e.Code },
	)

	ctx := context.Background()

	// 1. Get 空代码直接返回 false，不调用底层 redis
	item, hit, err := cache.Get(ctx, 100, "")
	assert.NoError(t, err)
	assert.False(t, hit)
	assert.Empty(t, item.Code)

	// 2. Set 空代码直接安全返回
	err = cache.Set(ctx, 100, "", testEntity{})
	assert.NoError(t, err)

	// 3. Delete 空代码直接返回
	err = cache.Delete(ctx, 100, "")
	assert.NoError(t, err)

	// 4. DeleteMulti 空代码列表直接返回
	err = cache.DeleteMulti(ctx, 100, []string{"", ""})
	assert.NoError(t, err)

	// 5. GetMulti 空代码列表直接返回空映射
	hits, misses, err := cache.GetMulti(ctx, 100, []string{})
	assert.NoError(t, err)
	assert.Empty(t, hits)
	assert.Nil(t, misses)

	// 6. SetMulti 空切片直接安全返回
	err = cache.SetMulti(ctx, 100, []testEntity{})
	assert.NoError(t, err)
}

func BenchmarkEntityCache_Key(b *testing.B) {
	cache := NewEntityCache[testEntity](
		nil,
		"role:detail",
		30*time.Minute,
		func(e testEntity) string { return e.Code },
	)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = cache.Key(1001, "admin_role_super")
	}
}

func BenchmarkEntityCache_JitterTTL_Parallel(b *testing.B) {
	cache := NewEntityCache[testEntity](
		nil,
		"role:detail",
		30*time.Minute,
		func(e testEntity) string { return e.Code },
	)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = cache.JitterTTL()
		}
	})
}

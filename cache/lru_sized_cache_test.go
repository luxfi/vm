// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cache_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
	"github.com/luxfi/vm/cache"
	"github.com/luxfi/vm/cache/cachetest"
)

func TestSizedLRU(t *testing.T) {
	c := cache.NewSizedLRU[ids.ID, int64](cachetest.IntSize, cachetest.IntSizeFunc)

	cachetest.Basic(t, c)
}

func TestSizedLRUEviction(t *testing.T) {
	c := cache.NewSizedLRU[ids.ID, int64](2*cachetest.IntSize, cachetest.IntSizeFunc)

	cachetest.Eviction(t, c)
}

func TestSizedLRUWrongKeyEvictionRegression(t *testing.T) {
	require := require.New(t)

	c := cache.NewSizedLRU[string, struct{}](
		3,
		func(key string, _ struct{}) int {
			return len(key)
		},
	)

	c.Put("a", struct{}{})
	c.Put("b", struct{}{})
	c.Put("c", struct{}{})
	c.Put("dd", struct{}{})

	_, ok := c.Get("a")
	require.False(ok)

	_, ok = c.Get("b")
	require.False(ok)

	_, ok = c.Get("c")
	require.True(ok)

	_, ok = c.Get("dd")
	require.True(ok)
}

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package rpcdb

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
)

// startZAPServer spawns a ZAPServer over an in-memory listener bound to
// 127.0.0.1:0, returns the addr + the server (for shutdown).
func startZAPServer(t *testing.T, db database.Database) (string, *ZAPServer, context.CancelFunc) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := NewZAPServer(db)
	s.ListenOn(listener)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = s.Serve(ctx)
	}()

	// Wait for Serve to fully install accept loop.
	time.Sleep(50 * time.Millisecond)
	return listener.Addr().String(), s, cancel
}

// TestZAPServer_HasGetPutDelete exercises the four primitive ops.
func TestZAPServer_HasGetPutDelete(t *testing.T) {
	require := require.New(t)
	mem := memdb.New()
	addr, srv, cancel := startZAPServer(t, mem)
	defer cancel()
	defer srv.Close()

	conn, err := zapwire.Dial(context.Background(), addr, nil)
	require.NoError(err)
	defer conn.Close()

	ctx := context.Background()

	// Has (key absent) → has=false, err=NotFound
	{
		buf := zapwire.GetBuffer()
		buf.WriteBytes([]byte("foo"))
		_, resp, err := conn.Call(ctx, MsgDBHas, buf.Bytes())
		zapwire.PutBuffer(buf)
		require.NoError(err)
		r := zapwire.NewReader(resp)
		hasB, _ := r.ReadUint8()
		errB, _ := r.ReadUint8()
		require.Equal(uint8(0), hasB)
		require.Equal(dbErrUnspecified, errB) // memdb returns no err on Has-miss
	}

	// Put
	{
		buf := zapwire.GetBuffer()
		buf.WriteBytes([]byte("foo"))
		buf.WriteBytes([]byte("bar"))
		_, resp, err := conn.Call(ctx, MsgDBPut, buf.Bytes())
		zapwire.PutBuffer(buf)
		require.NoError(err)
		r := zapwire.NewReader(resp)
		errB, _ := r.ReadUint8()
		require.Equal(dbErrUnspecified, errB)
	}

	// Has (key present) → has=true
	{
		buf := zapwire.GetBuffer()
		buf.WriteBytes([]byte("foo"))
		_, resp, err := conn.Call(ctx, MsgDBHas, buf.Bytes())
		zapwire.PutBuffer(buf)
		require.NoError(err)
		r := zapwire.NewReader(resp)
		hasB, _ := r.ReadUint8()
		errB, _ := r.ReadUint8()
		require.Equal(uint8(1), hasB)
		require.Equal(dbErrUnspecified, errB)
	}

	// Get
	{
		buf := zapwire.GetBuffer()
		buf.WriteBytes([]byte("foo"))
		_, resp, err := conn.Call(ctx, MsgDBGet, buf.Bytes())
		zapwire.PutBuffer(buf)
		require.NoError(err)
		r := zapwire.NewReader(resp)
		val, _ := r.ReadBytes()
		errB, _ := r.ReadUint8()
		require.Equal([]byte("bar"), val)
		require.Equal(dbErrUnspecified, errB)
	}

	// Get (missing) → empty value, err=NotFound
	{
		buf := zapwire.GetBuffer()
		buf.WriteBytes([]byte("absent"))
		_, resp, err := conn.Call(ctx, MsgDBGet, buf.Bytes())
		zapwire.PutBuffer(buf)
		require.NoError(err)
		r := zapwire.NewReader(resp)
		val, _ := r.ReadBytes()
		errB, _ := r.ReadUint8()
		require.Empty(val)
		require.Equal(dbErrNotFound, errB)
	}

	// Delete
	{
		buf := zapwire.GetBuffer()
		buf.WriteBytes([]byte("foo"))
		_, resp, err := conn.Call(ctx, MsgDBDelete, buf.Bytes())
		zapwire.PutBuffer(buf)
		require.NoError(err)
		r := zapwire.NewReader(resp)
		errB, _ := r.ReadUint8()
		require.Equal(dbErrUnspecified, errB)
	}

	// Get post-delete → NotFound
	{
		buf := zapwire.GetBuffer()
		buf.WriteBytes([]byte("foo"))
		_, resp, err := conn.Call(ctx, MsgDBGet, buf.Bytes())
		zapwire.PutBuffer(buf)
		require.NoError(err)
		r := zapwire.NewReader(resp)
		_, _ = r.ReadBytes()
		errB, _ := r.ReadUint8()
		require.Equal(dbErrNotFound, errB)
	}
}

// TestZAPServer_WriteBatch_AndIterate covers batched writes plus the
// iterator path used by cevm's load_persisted snapshot_with_prefix.
func TestZAPServer_WriteBatch_AndIterate(t *testing.T) {
	require := require.New(t)
	mem := memdb.New()
	addr, srv, cancel := startZAPServer(t, mem)
	defer cancel()
	defer srv.Close()

	conn, err := zapwire.Dial(context.Background(), addr, nil)
	require.NoError(err)
	defer conn.Close()

	ctx := context.Background()

	// WriteBatch: 3 puts (prefix p:), 1 delete (no-op since absent).
	{
		buf := zapwire.GetBuffer()
		buf.WriteUint32(3)
		buf.WriteBytes([]byte("p:1"))
		buf.WriteBytes([]byte("v1"))
		buf.WriteBytes([]byte("p:2"))
		buf.WriteBytes([]byte("v2"))
		buf.WriteBytes([]byte("q:3"))
		buf.WriteBytes([]byte("v3"))
		buf.WriteUint32(1)
		buf.WriteBytes([]byte("absent"))
		_, resp, err := conn.Call(ctx, MsgDBWriteBatch, buf.Bytes())
		zapwire.PutBuffer(buf)
		require.NoError(err)
		r := zapwire.NewReader(resp)
		errB, _ := r.ReadUint8()
		require.Equal(dbErrUnspecified, errB)
	}

	// IteratorNew with prefix "p:"
	var iterID uint64
	{
		buf := zapwire.GetBuffer()
		buf.WriteBytes(nil)         // start
		buf.WriteBytes([]byte("p:")) // prefix
		_, resp, err := conn.Call(ctx, MsgDBIteratorNew, buf.Bytes())
		zapwire.PutBuffer(buf)
		require.NoError(err)
		r := zapwire.NewReader(resp)
		iterID, _ = r.ReadUint64()
	}

	// IteratorNext — collect.
	collected := map[string]string{}
	for {
		buf := zapwire.GetBuffer()
		buf.WriteUint64(iterID)
		_, resp, err := conn.Call(ctx, MsgDBIteratorNext, buf.Bytes())
		zapwire.PutBuffer(buf)
		require.NoError(err)
		r := zapwire.NewReader(resp)
		n, _ := r.ReadUint32()
		if n == 0 {
			break
		}
		for i := uint32(0); i < n; i++ {
			k, _ := r.ReadBytes()
			v, _ := r.ReadBytes()
			collected[string(k)] = string(v)
		}
	}

	// IteratorRelease
	{
		buf := zapwire.GetBuffer()
		buf.WriteUint64(iterID)
		_, resp, err := conn.Call(ctx, MsgDBIteratorRelease, buf.Bytes())
		zapwire.PutBuffer(buf)
		require.NoError(err)
		r := zapwire.NewReader(resp)
		errB, _ := r.ReadUint8()
		require.Equal(dbErrUnspecified, errB)
	}

	require.Equal(map[string]string{"p:1": "v1", "p:2": "v2"}, collected)
}

// TestZAPServer_ParityWithMemDB writes/reads via wire and via direct
// memdb Get to confirm both paths see the same state — proves the ZAP
// round-trip preserves bytes exactly.
func TestZAPServer_ParityWithMemDB(t *testing.T) {
	require := require.New(t)
	mem := memdb.New()
	addr, srv, cancel := startZAPServer(t, mem)
	defer cancel()
	defer srv.Close()

	conn, err := zapwire.Dial(context.Background(), addr, nil)
	require.NoError(err)
	defer conn.Close()

	ctx := context.Background()

	key := []byte{0x42, 0x00, 0x01, 0xff}
	value := make([]byte, 256)
	for i := range value {
		value[i] = byte(i)
	}

	// Put via wire.
	buf := zapwire.GetBuffer()
	buf.WriteBytes(key)
	buf.WriteBytes(value)
	_, _, err = conn.Call(ctx, MsgDBPut, buf.Bytes())
	zapwire.PutBuffer(buf)
	require.NoError(err)

	// Read directly.
	got, dErr := mem.Get(key)
	require.NoError(dErr)
	require.Equal(value, got)

	// Read via wire.
	buf2 := zapwire.GetBuffer()
	buf2.WriteBytes(key)
	_, resp, err := conn.Call(ctx, MsgDBGet, buf2.Bytes())
	zapwire.PutBuffer(buf2)
	require.NoError(err)
	r := zapwire.NewReader(resp)
	wireVal, _ := r.ReadBytes()
	require.Equal(value, wireVal)
}

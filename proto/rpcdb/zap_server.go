// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// ZAPServer is the ZAP-native rpcdb server: a database.Database wrapped
// with handlers for the ZAP db wire protocol. Mirrors db_server.go (the
// gRPC version) but speaks the binary ZAP framing — see
// ~/work/lux/api/zap/transport.go and zapdb_client.hpp on the cevm side.
//
// The Go side is build-tag-free (this is the default); the gRPC server
// in db_server.go is tagged `grpc` and mutually exclusive.

package rpcdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/database"
)

// ZAP db channel MsgType IDs. Local to this listener — do NOT collide
// with VM lifecycle MsgTypes (1..31) or sender (40..49) or warp
// (50..59), but irrelevant in practice because this is a separate
// ZAP listener.
const (
	MsgDBHas             zapwire.MessageType = 1
	MsgDBGet             zapwire.MessageType = 2
	MsgDBPut             zapwire.MessageType = 3
	MsgDBDelete          zapwire.MessageType = 4
	MsgDBWriteBatch      zapwire.MessageType = 5
	MsgDBCompact         zapwire.MessageType = 6
	MsgDBClose           zapwire.MessageType = 7
	MsgDBHealthCheck     zapwire.MessageType = 8
	MsgDBIteratorNew     zapwire.MessageType = 9
	MsgDBIteratorNext    zapwire.MessageType = 10
	MsgDBIteratorError   zapwire.MessageType = 11
	MsgDBIteratorRelease zapwire.MessageType = 12
)

// Error byte values on the wire (matches proto/zap/rpcdb.Error).
const (
	dbErrUnspecified uint8 = 0
	dbErrClosed      uint8 = 1
	dbErrNotFound    uint8 = 2
)

// errToByte maps a database error to the on-the-wire single-byte code.
func errToByte(err error) uint8 {
	switch {
	case err == nil:
		return dbErrUnspecified
	case errors.Is(err, database.ErrClosed):
		return dbErrClosed
	case errors.Is(err, database.ErrNotFound):
		return dbErrNotFound
	default:
		return dbErrUnspecified
	}
}

// errToTransport returns nil for known sentinel errors (so they're
// reported in-band via the byte code), and the actual error otherwise
// (so it surfaces as a transport-level error response). Same split
// rule as the gRPC ErrorToRPCError.
func errToTransport(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, database.ErrClosed) || errors.Is(err, database.ErrNotFound) {
		return nil
	}
	return err
}

const iterationBatchBytes = 128 * 1024

// ZAPServer is a database.Database served over the ZAP transport.
type ZAPServer struct {
	db database.Database

	listener *zapwire.Listener
	server   *zapwire.Server

	iteratorMu     sync.RWMutex
	nextIteratorID uint64
	iterators      map[uint64]database.Iterator
}

// NewZAPServer wraps a database.Database for serving over ZAP.
func NewZAPServer(db database.Database) *ZAPServer {
	return &ZAPServer{
		db:        db,
		iterators: make(map[uint64]database.Iterator),
	}
}

// Listen binds the ZAP listener.
func (s *ZAPServer) Listen(addr string) error {
	listener, err := zapwire.Listen(addr, nil)
	if err != nil {
		return fmt.Errorf("rpcdb: zap listen failed: %w", err)
	}
	s.listener = listener
	s.server = zapwire.NewServer(listener, zapwire.HandlerFunc(s.handle))
	return nil
}

// ListenOn wraps an existing net.Listener (for ephemeral ports etc.).
func (s *ZAPServer) ListenOn(raw net.Listener) {
	s.listener = zapwire.NewListener(raw, nil)
	s.server = zapwire.NewServer(s.listener, zapwire.HandlerFunc(s.handle))
}

// Addr returns the bound address.
func (s *ZAPServer) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Serve blocks until ctx is cancelled or Close is called.
func (s *ZAPServer) Serve(ctx context.Context) error {
	if s.server == nil {
		return errors.New("rpcdb zap server: not initialized — call Listen first")
	}
	return s.server.Serve(ctx)
}

// Close releases all iterators and closes the listener. Caller is
// expected to also cancel the context passed to Serve so the accept
// loop exits cleanly. We deliberately do NOT call s.server.Close()
// because the upstream zapwire.Server.Close races with in-flight
// accept (it nils its conns map mid-Serve, causing "assignment to
// entry in nil map"). Closing the listener is enough to make Accept
// return; ctx cancellation does the rest.
func (s *ZAPServer) Close() error {
	s.iteratorMu.Lock()
	for id, it := range s.iterators {
		it.Release()
		delete(s.iterators, id)
	}
	s.iteratorMu.Unlock()

	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *ZAPServer) handle(ctx context.Context, msgType zapwire.MessageType, payload []byte) (zapwire.MessageType, []byte, error) {
	switch msgType {
	case MsgDBHas:
		return s.handleHas(payload)
	case MsgDBGet:
		return s.handleGet(payload)
	case MsgDBPut:
		return s.handlePut(payload)
	case MsgDBDelete:
		return s.handleDelete(payload)
	case MsgDBWriteBatch:
		return s.handleWriteBatch(payload)
	case MsgDBCompact:
		return s.handleCompact(payload)
	case MsgDBClose:
		return s.handleClose(payload)
	case MsgDBHealthCheck:
		return s.handleHealthCheck(ctx)
	case MsgDBIteratorNew:
		return s.handleIteratorNew(payload)
	case MsgDBIteratorNext:
		return s.handleIteratorNext(payload)
	case MsgDBIteratorError:
		return s.handleIteratorError(payload)
	case MsgDBIteratorRelease:
		return s.handleIteratorRelease(payload)
	default:
		return 0, nil, fmt.Errorf("rpcdb: unknown msg type %d", msgType)
	}
}

func (s *ZAPServer) handleHas(payload []byte) (zapwire.MessageType, []byte, error) {
	r := zapwire.NewReader(payload)
	key, err := r.ReadBytes()
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb Has decode: %w", err)
	}
	has, dbErr := s.db.Has(key)
	if t := errToTransport(dbErr); t != nil {
		return 0, nil, t
	}
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	if has {
		buf.WriteUint8(1)
	} else {
		buf.WriteUint8(0)
	}
	buf.WriteUint8(errToByte(dbErr))
	return MsgDBHas, append([]byte(nil), buf.Bytes()...), nil
}

func (s *ZAPServer) handleGet(payload []byte) (zapwire.MessageType, []byte, error) {
	r := zapwire.NewReader(payload)
	key, err := r.ReadBytes()
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb Get decode: %w", err)
	}
	value, dbErr := s.db.Get(key)
	if t := errToTransport(dbErr); t != nil {
		return 0, nil, t
	}
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	buf.WriteBytes(value)
	buf.WriteUint8(errToByte(dbErr))
	return MsgDBGet, append([]byte(nil), buf.Bytes()...), nil
}

func (s *ZAPServer) handlePut(payload []byte) (zapwire.MessageType, []byte, error) {
	r := zapwire.NewReader(payload)
	key, err := r.ReadBytes()
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb Put decode key: %w", err)
	}
	value, err := r.ReadBytes()
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb Put decode value: %w", err)
	}
	dbErr := s.db.Put(key, value)
	if t := errToTransport(dbErr); t != nil {
		return 0, nil, t
	}
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	buf.WriteUint8(errToByte(dbErr))
	return MsgDBPut, append([]byte(nil), buf.Bytes()...), nil
}

func (s *ZAPServer) handleDelete(payload []byte) (zapwire.MessageType, []byte, error) {
	r := zapwire.NewReader(payload)
	key, err := r.ReadBytes()
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb Delete decode: %w", err)
	}
	dbErr := s.db.Delete(key)
	if t := errToTransport(dbErr); t != nil {
		return 0, nil, t
	}
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	buf.WriteUint8(errToByte(dbErr))
	return MsgDBDelete, append([]byte(nil), buf.Bytes()...), nil
}

func (s *ZAPServer) handleWriteBatch(payload []byte) (zapwire.MessageType, []byte, error) {
	r := zapwire.NewReader(payload)

	nputs, err := r.ReadUint32()
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb WriteBatch decode nputs: %w", err)
	}
	batch := s.db.NewBatch()
	for i := uint32(0); i < nputs; i++ {
		key, err := r.ReadBytes()
		if err != nil {
			return 0, nil, fmt.Errorf("rpcdb WriteBatch put[%d] key: %w", i, err)
		}
		value, err := r.ReadBytes()
		if err != nil {
			return 0, nil, fmt.Errorf("rpcdb WriteBatch put[%d] value: %w", i, err)
		}
		if err := batch.Put(key, value); err != nil {
			return 0, nil, fmt.Errorf("rpcdb WriteBatch batch.Put: %w", err)
		}
	}

	ndels, err := r.ReadUint32()
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb WriteBatch decode ndels: %w", err)
	}
	for i := uint32(0); i < ndels; i++ {
		key, err := r.ReadBytes()
		if err != nil {
			return 0, nil, fmt.Errorf("rpcdb WriteBatch del[%d]: %w", i, err)
		}
		if err := batch.Delete(key); err != nil {
			return 0, nil, fmt.Errorf("rpcdb WriteBatch batch.Delete: %w", err)
		}
	}

	dbErr := batch.Write()
	if t := errToTransport(dbErr); t != nil {
		return 0, nil, t
	}
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	buf.WriteUint8(errToByte(dbErr))
	return MsgDBWriteBatch, append([]byte(nil), buf.Bytes()...), nil
}

func (s *ZAPServer) handleCompact(payload []byte) (zapwire.MessageType, []byte, error) {
	r := zapwire.NewReader(payload)
	start, err := r.ReadBytes()
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb Compact decode start: %w", err)
	}
	limit, err := r.ReadBytes()
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb Compact decode limit: %w", err)
	}
	dbErr := s.db.Compact(start, limit)
	if t := errToTransport(dbErr); t != nil {
		return 0, nil, t
	}
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	buf.WriteUint8(errToByte(dbErr))
	return MsgDBCompact, append([]byte(nil), buf.Bytes()...), nil
}

func (s *ZAPServer) handleClose(_ []byte) (zapwire.MessageType, []byte, error) {
	dbErr := s.db.Close()
	if t := errToTransport(dbErr); t != nil {
		return 0, nil, t
	}
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	buf.WriteUint8(errToByte(dbErr))
	return MsgDBClose, append([]byte(nil), buf.Bytes()...), nil
}

func (s *ZAPServer) handleHealthCheck(ctx context.Context) (zapwire.MessageType, []byte, error) {
	health, err := s.db.HealthCheck(ctx)
	if err != nil {
		return 0, nil, err
	}
	details, err := json.Marshal(health)
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb HealthCheck marshal: %w", err)
	}
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	buf.WriteBytes(details)
	return MsgDBHealthCheck, append([]byte(nil), buf.Bytes()...), nil
}

func (s *ZAPServer) handleIteratorNew(payload []byte) (zapwire.MessageType, []byte, error) {
	r := zapwire.NewReader(payload)
	start, err := r.ReadBytes()
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb IteratorNew decode start: %w", err)
	}
	prefix, err := r.ReadBytes()
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb IteratorNew decode prefix: %w", err)
	}

	it := s.db.NewIteratorWithStartAndPrefix(start, prefix)

	s.iteratorMu.Lock()
	id := s.nextIteratorID
	s.iterators[id] = it
	s.nextIteratorID++
	s.iteratorMu.Unlock()

	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	buf.WriteUint64(id)
	return MsgDBIteratorNew, append([]byte(nil), buf.Bytes()...), nil
}

func (s *ZAPServer) handleIteratorNext(payload []byte) (zapwire.MessageType, []byte, error) {
	r := zapwire.NewReader(payload)
	id, err := r.ReadUint64()
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb IteratorNext decode id: %w", err)
	}

	s.iteratorMu.RLock()
	it, ok := s.iterators[id]
	s.iteratorMu.RUnlock()
	if !ok {
		return 0, nil, fmt.Errorf("rpcdb IteratorNext: unknown iterator %d", id)
	}

	type kv struct{ k, v []byte }
	var (
		size  int
		batch []kv
	)
	for size < iterationBatchBytes && it.Next() {
		k := it.Key()
		v := it.Value()
		size += len(k) + len(v)
		// Copy because the iterator's slices may be reused on next call.
		kc := make([]byte, len(k))
		copy(kc, k)
		vc := make([]byte, len(v))
		copy(vc, v)
		batch = append(batch, kv{k: kc, v: vc})
	}

	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	buf.WriteUint32(uint32(len(batch)))
	for _, e := range batch {
		buf.WriteBytes(e.k)
		buf.WriteBytes(e.v)
	}
	return MsgDBIteratorNext, append([]byte(nil), buf.Bytes()...), nil
}

func (s *ZAPServer) handleIteratorError(payload []byte) (zapwire.MessageType, []byte, error) {
	r := zapwire.NewReader(payload)
	id, err := r.ReadUint64()
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb IteratorError decode id: %w", err)
	}

	s.iteratorMu.RLock()
	it, ok := s.iterators[id]
	s.iteratorMu.RUnlock()
	if !ok {
		return 0, nil, fmt.Errorf("rpcdb IteratorError: unknown iterator %d", id)
	}
	dbErr := it.Error()
	if t := errToTransport(dbErr); t != nil {
		return 0, nil, t
	}
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	buf.WriteUint8(errToByte(dbErr))
	return MsgDBIteratorError, append([]byte(nil), buf.Bytes()...), nil
}

func (s *ZAPServer) handleIteratorRelease(payload []byte) (zapwire.MessageType, []byte, error) {
	r := zapwire.NewReader(payload)
	id, err := r.ReadUint64()
	if err != nil {
		return 0, nil, fmt.Errorf("rpcdb IteratorRelease decode id: %w", err)
	}

	s.iteratorMu.Lock()
	it, ok := s.iterators[id]
	if !ok {
		s.iteratorMu.Unlock()
		buf := zapwire.GetBuffer()
		defer zapwire.PutBuffer(buf)
		buf.WriteUint8(dbErrUnspecified)
		return MsgDBIteratorRelease, append([]byte(nil), buf.Bytes()...), nil
	}
	delete(s.iterators, id)
	s.iteratorMu.Unlock()

	dbErr := it.Error()
	it.Release()
	if t := errToTransport(dbErr); t != nil {
		return 0, nil, t
	}
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	buf.WriteUint8(errToByte(dbErr))
	return MsgDBIteratorRelease, append([]byte(nil), buf.Bytes()...), nil
}

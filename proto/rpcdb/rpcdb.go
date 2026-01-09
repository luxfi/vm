// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package rpcdb provides database RPC functionality
package rpcdb

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/luxfi/database"
	rpcdbpb "github.com/luxfi/node/proto/pb/rpcdb"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	_ database.Database      = (*DatabaseClient)(nil)
	_ rpcdbpb.DatabaseServer = (*DatabaseServer)(nil)
)

// DatabaseServer is a database server that listens over RPC.
type DatabaseServer struct {
	rpcdbpb.UnimplementedDatabaseServer
	db database.Database

	iteratorLock   sync.RWMutex
	nextIteratorID uint64
	iterators      map[uint64]database.Iterator
}

// NewServer returns a new database server
func NewServer(db database.Database) *DatabaseServer {
	return &DatabaseServer{
		db:        db,
		iterators: make(map[uint64]database.Iterator),
	}
}

func (db *DatabaseServer) Has(ctx context.Context, req *rpcdbpb.HasRequest) (*rpcdbpb.HasResponse, error) {
	has, err := db.db.Has(req.Key)
	if err != nil {
		return &rpcdbpb.HasResponse{
			Has: false,
			Err: errorToRPCError(err),
		}, nil
	}
	return &rpcdbpb.HasResponse{
		Has: has,
		Err: rpcdbpb.Error_ERROR_UNSPECIFIED,
	}, nil
}

func (db *DatabaseServer) Get(ctx context.Context, req *rpcdbpb.GetRequest) (*rpcdbpb.GetResponse, error) {
	value, err := db.db.Get(req.Key)
	if err != nil {
		return &rpcdbpb.GetResponse{
			Value: nil,
			Err:   errorToRPCError(err),
		}, nil
	}
	return &rpcdbpb.GetResponse{
		Value: value,
		Err:   rpcdbpb.Error_ERROR_UNSPECIFIED,
	}, nil
}

func (db *DatabaseServer) Put(ctx context.Context, req *rpcdbpb.PutRequest) (*rpcdbpb.PutResponse, error) {
	err := db.db.Put(req.Key, req.Value)
	return &rpcdbpb.PutResponse{
		Err: errorToRPCError(err),
	}, nil
}

func (db *DatabaseServer) Delete(ctx context.Context, req *rpcdbpb.DeleteRequest) (*rpcdbpb.DeleteResponse, error) {
	err := db.db.Delete(req.Key)
	return &rpcdbpb.DeleteResponse{
		Err: errorToRPCError(err),
	}, nil
}

func (db *DatabaseServer) WriteBatch(ctx context.Context, req *rpcdbpb.WriteBatchRequest) (*rpcdbpb.WriteBatchResponse, error) {
	batch := db.db.NewBatch()

	for _, put := range req.Puts {
		if err := batch.Put(put.Key, put.Value); err != nil {
			return &rpcdbpb.WriteBatchResponse{
				Err: errorToRPCError(err),
			}, nil
		}
	}

	for _, del := range req.Deletes {
		if err := batch.Delete(del.Key); err != nil {
			return &rpcdbpb.WriteBatchResponse{
				Err: errorToRPCError(err),
			}, nil
		}
	}

	err := batch.Write()
	return &rpcdbpb.WriteBatchResponse{
		Err: errorToRPCError(err),
	}, nil
}

func (db *DatabaseServer) Compact(ctx context.Context, req *rpcdbpb.CompactRequest) (*rpcdbpb.CompactResponse, error) {
	err := db.db.Compact(req.Start, req.Limit)
	return &rpcdbpb.CompactResponse{
		Err: errorToRPCError(err),
	}, nil
}

func (db *DatabaseServer) Close(ctx context.Context, req *rpcdbpb.CloseRequest) (*rpcdbpb.CloseResponse, error) {
	err := db.db.Close()
	return &rpcdbpb.CloseResponse{
		Err: errorToRPCError(err),
	}, nil
}

func (db *DatabaseServer) HealthCheck(ctx context.Context, req *emptypb.Empty) (*rpcdbpb.HealthCheckResponse, error) {
	health, err := db.db.HealthCheck(ctx)
	if err != nil {
		return &rpcdbpb.HealthCheckResponse{
			Details: []byte(err.Error()),
		}, nil
	}

	// Convert health data to bytes
	healthBytes := []byte("healthy")
	if health != nil {
		if str, ok := health.(string); ok {
			healthBytes = []byte(str)
		}
	}

	return &rpcdbpb.HealthCheckResponse{
		Details: healthBytes,
	}, nil
}

func (db *DatabaseServer) NewIteratorWithStartAndPrefix(ctx context.Context, req *rpcdbpb.NewIteratorWithStartAndPrefixRequest) (*rpcdbpb.NewIteratorWithStartAndPrefixResponse, error) {
	it := db.db.NewIteratorWithStartAndPrefix(req.Start, req.Prefix)

	db.iteratorLock.Lock()
	id := db.nextIteratorID
	db.nextIteratorID++
	db.iterators[id] = it
	db.iteratorLock.Unlock()

	return &rpcdbpb.NewIteratorWithStartAndPrefixResponse{
		Id: id,
	}, nil
}

func (db *DatabaseServer) IteratorNext(ctx context.Context, req *rpcdbpb.IteratorNextRequest) (*rpcdbpb.IteratorNextResponse, error) {
	db.iteratorLock.RLock()
	it, ok := db.iterators[req.Id]
	db.iteratorLock.RUnlock()

	if !ok {
		return &rpcdbpb.IteratorNextResponse{
			Data: nil,
		}, nil
	}

	// Collect data until we have a reasonable batch or iterator is exhausted
	var data []*rpcdbpb.PutRequest
	const maxBatchSize = 100

	for i := 0; i < maxBatchSize && it.Next(); i++ {
		data = append(data, &rpcdbpb.PutRequest{
			Key:   it.Key(),
			Value: it.Value(),
		})
	}

	return &rpcdbpb.IteratorNextResponse{
		Data: data,
	}, nil
}

func (db *DatabaseServer) IteratorError(ctx context.Context, req *rpcdbpb.IteratorErrorRequest) (*rpcdbpb.IteratorErrorResponse, error) {
	db.iteratorLock.RLock()
	it, ok := db.iterators[req.Id]
	db.iteratorLock.RUnlock()

	if !ok {
		return &rpcdbpb.IteratorErrorResponse{
			Err: rpcdbpb.Error_ERROR_NOT_FOUND,
		}, nil
	}

	err := it.Error()
	return &rpcdbpb.IteratorErrorResponse{
		Err: errorToRPCError(err),
	}, nil
}

func (db *DatabaseServer) IteratorRelease(ctx context.Context, req *rpcdbpb.IteratorReleaseRequest) (*rpcdbpb.IteratorReleaseResponse, error) {
	db.iteratorLock.Lock()
	it, ok := db.iterators[req.Id]
	if ok {
		it.Release()
		delete(db.iterators, req.Id)
	}
	db.iteratorLock.Unlock()

	var err rpcdbpb.Error
	if !ok {
		err = rpcdbpb.Error_ERROR_NOT_FOUND
	} else {
		err = rpcdbpb.Error_ERROR_UNSPECIFIED
	}

	return &rpcdbpb.IteratorReleaseResponse{
		Err: err,
	}, nil
}

// DatabaseClient is a database client
type DatabaseClient struct {
	client rpcdbpb.DatabaseClient
}

// NewClient returns a new database client
func NewClient(client rpcdbpb.DatabaseClient) *DatabaseClient {
	return &DatabaseClient{
		client: client,
	}
}

func (db *DatabaseClient) Has(key []byte) (bool, error) {
	resp, err := db.client.Has(context.Background(), &rpcdbpb.HasRequest{
		Key: key,
	})
	if err != nil {
		return false, err
	}
	if resp.Err != rpcdbpb.Error_ERROR_UNSPECIFIED {
		return false, rpcErrorToError(resp.Err)
	}
	return resp.Has, nil
}

func (db *DatabaseClient) Get(key []byte) ([]byte, error) {
	resp, err := db.client.Get(context.Background(), &rpcdbpb.GetRequest{
		Key: key,
	})
	if err != nil {
		return nil, err
	}
	if resp.Err != rpcdbpb.Error_ERROR_UNSPECIFIED {
		return nil, rpcErrorToError(resp.Err)
	}
	return resp.Value, nil
}

func (db *DatabaseClient) Put(key []byte, value []byte) error {
	resp, err := db.client.Put(context.Background(), &rpcdbpb.PutRequest{
		Key:   key,
		Value: value,
	})
	if err != nil {
		return err
	}
	if resp.Err != rpcdbpb.Error_ERROR_UNSPECIFIED {
		return rpcErrorToError(resp.Err)
	}
	return nil
}

func (db *DatabaseClient) Delete(key []byte) error {
	resp, err := db.client.Delete(context.Background(), &rpcdbpb.DeleteRequest{
		Key: key,
	})
	if err != nil {
		return err
	}
	if resp.Err != rpcdbpb.Error_ERROR_UNSPECIFIED {
		return rpcErrorToError(resp.Err)
	}
	return nil
}

func (db *DatabaseClient) NewBatch() database.Batch {
	return &batch{
		db:      db,
		puts:    []*rpcdbpb.PutRequest{},
		deletes: []*rpcdbpb.DeleteRequest{},
	}
}

func (db *DatabaseClient) NewIterator() database.Iterator {
	return db.NewIteratorWithStartAndPrefix(nil, nil)
}

func (db *DatabaseClient) NewIteratorWithStart(start []byte) database.Iterator {
	return db.NewIteratorWithStartAndPrefix(start, nil)
}

func (db *DatabaseClient) NewIteratorWithPrefix(prefix []byte) database.Iterator {
	return db.NewIteratorWithStartAndPrefix(nil, prefix)
}

func (db *DatabaseClient) NewIteratorWithStartAndPrefix(start []byte, prefix []byte) database.Iterator {
	resp, err := db.client.NewIteratorWithStartAndPrefix(context.Background(), &rpcdbpb.NewIteratorWithStartAndPrefixRequest{
		Start:  start,
		Prefix: prefix,
	})
	if err != nil {
		return &iterator{
			db:  db,
			err: err,
		}
	}
	return &iterator{
		db: db,
		id: resp.Id,
	}
}

// Backup is not supported over the RPC database client.
func (db *DatabaseClient) Backup(_ io.Writer, _ uint64) (uint64, error) {
	return 0, errors.New("rpcdb: backup not supported")
}

// Load is not supported over the RPC database client.
func (db *DatabaseClient) Load(_ io.Reader) error {
	return errors.New("rpcdb: load not supported")
}

func (db *DatabaseClient) Compact(start []byte, limit []byte) error {
	resp, err := db.client.Compact(context.Background(), &rpcdbpb.CompactRequest{
		Start: start,
		Limit: limit,
	})
	if err != nil {
		return err
	}
	if resp.Err != rpcdbpb.Error_ERROR_UNSPECIFIED {
		return rpcErrorToError(resp.Err)
	}
	return nil
}

func (db *DatabaseClient) Sync() error {
	// RPC database sync is a no-op on client side
	// The server handles persistence
	return nil
}

func (db *DatabaseClient) Close() error {
	resp, err := db.client.Close(context.Background(), &rpcdbpb.CloseRequest{})
	if err != nil {
		return err
	}
	if resp.Err != rpcdbpb.Error_ERROR_UNSPECIFIED {
		return rpcErrorToError(resp.Err)
	}
	return nil
}

func (db *DatabaseClient) HealthCheck(ctx context.Context) (interface{}, error) {
	resp, err := db.client.HealthCheck(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	return resp.Details, nil
}

type batch struct {
	db      *DatabaseClient
	puts    []*rpcdbpb.PutRequest
	deletes []*rpcdbpb.DeleteRequest
	size    int
}

func (b *batch) Put(key, value []byte) error {
	b.puts = append(b.puts, &rpcdbpb.PutRequest{
		Key:   key,
		Value: value,
	})
	b.size += len(key) + len(value)
	return nil
}

func (b *batch) Delete(key []byte) error {
	b.deletes = append(b.deletes, &rpcdbpb.DeleteRequest{
		Key: key,
	})
	b.size += len(key)
	return nil
}

func (b *batch) Size() int {
	return b.size
}

func (b *batch) Write() error {
	resp, err := b.db.client.WriteBatch(context.Background(), &rpcdbpb.WriteBatchRequest{
		Puts:    b.puts,
		Deletes: b.deletes,
	})
	if err != nil {
		return err
	}
	if resp.Err != rpcdbpb.Error_ERROR_UNSPECIFIED {
		return rpcErrorToError(resp.Err)
	}
	return nil
}

func (b *batch) Reset() {
	b.puts = b.puts[:0]
	b.deletes = b.deletes[:0]
	b.size = 0
}

func (b *batch) Replay(w database.KeyValueWriterDeleter) error {
	for _, put := range b.puts {
		if err := w.Put(put.Key, put.Value); err != nil {
			return err
		}
	}
	for _, del := range b.deletes {
		if err := w.Delete(del.Key); err != nil {
			return err
		}
	}
	return nil
}

func (b *batch) Inner() database.Batch {
	return b
}

type iterator struct {
	db        *DatabaseClient
	id        uint64
	data      []*rpcdbpb.PutRequest
	dataIndex int
	err       error
	closed    bool
}

func (it *iterator) Next() bool {
	if it.err != nil || it.closed {
		return false
	}

	// If we have data left from previous fetch, use it
	if it.dataIndex < len(it.data)-1 {
		it.dataIndex++
		return true
	}

	// Fetch next batch
	resp, err := it.db.client.IteratorNext(context.Background(), &rpcdbpb.IteratorNextRequest{
		Id: it.id,
	})
	if err != nil {
		it.err = err
		return false
	}

	if len(resp.Data) == 0 {
		return false
	}

	it.data = resp.Data
	it.dataIndex = 0
	return true
}

func (it *iterator) Error() error {
	if it.err != nil {
		return it.err
	}

	resp, err := it.db.client.IteratorError(context.Background(), &rpcdbpb.IteratorErrorRequest{
		Id: it.id,
	})
	if err != nil {
		return err
	}
	if resp.Err != rpcdbpb.Error_ERROR_UNSPECIFIED {
		return rpcErrorToError(resp.Err)
	}
	return nil
}

func (it *iterator) Key() []byte {
	if it.dataIndex >= 0 && it.dataIndex < len(it.data) {
		return it.data[it.dataIndex].Key
	}
	return nil
}

func (it *iterator) Value() []byte {
	if it.dataIndex >= 0 && it.dataIndex < len(it.data) {
		return it.data[it.dataIndex].Value
	}
	return nil
}

func (it *iterator) Release() {
	if it.closed {
		return
	}
	it.closed = true
	it.db.client.IteratorRelease(context.Background(), &rpcdbpb.IteratorReleaseRequest{
		Id: it.id,
	})
}

// Helper functions for error conversion
func errorToRPCError(err error) rpcdbpb.Error {
	if err == nil {
		return rpcdbpb.Error_ERROR_UNSPECIFIED
	}
	switch err {
	case database.ErrNotFound:
		return rpcdbpb.Error_ERROR_NOT_FOUND
	case database.ErrClosed:
		return rpcdbpb.Error_ERROR_CLOSED
	default:
		// For any other error, we'll use CLOSED to indicate an error occurred
		// since we only have limited error types in the proto
		return rpcdbpb.Error_ERROR_CLOSED
	}
}

func rpcErrorToError(err rpcdbpb.Error) error {
	switch err {
	case rpcdbpb.Error_ERROR_UNSPECIFIED:
		return nil
	case rpcdbpb.Error_ERROR_NOT_FOUND:
		return database.ErrNotFound
	case rpcdbpb.Error_ERROR_CLOSED:
		return database.ErrClosed
	default:
		return database.ErrClosed
	}
}

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package proposervm

import (
	"net/http"

	"github.com/gorilla/rpc/v2"

	"github.com/luxfi/vm/utils/json"
)

// Service wraps proposervm for RPC/JSON-RPC access
type Service struct {
	vm *VM
}

// GetProposedHeightArgs are the arguments for GetProposedHeight
type GetProposedHeightArgs struct{}

// GetProposedHeightReply is the response from GetProposedHeight
type GetProposedHeightReply struct {
	// ProposedHeight is the P-Chain height that would be proposed
	// for the next block built on the current preferred block
	ProposedHeight uint64 `json:"proposedHeight"`
}

// GetProposedHeight returns the P-Chain height that would be proposed
// for the next block built on the current preferred block.
//
// Example JSON-RPC call:
//
//	curl -X POST --data '{
//	    "jsonrpc":"2.0",
//	    "id"     :1,
//	    "method" :"proposervm.getProposedHeight",
//	    "params" :{}
//	}' -H 'content-type:application/json;' http://127.0.0.1:9650/ext/bc/C/rpc
func (s *Service) GetProposedHeight(r *http.Request, _ *GetProposedHeightArgs, reply *GetProposedHeightReply) error {
	ctx := r.Context()

	s.vm.ctx.Lock.Lock()
	defer s.vm.ctx.Lock.Unlock()

	// Get the current preferred block
	preferredBlock, err := s.vm.getBlock(ctx, s.vm.preferred)
	if err != nil {
		return err
	}

	// Get the P-Chain height that would be proposed for a child of this block
	proposedHeight, err := preferredBlock.selectChildPChainHeight(ctx)
	if err != nil {
		return err
	}

	reply.ProposedHeight = proposedHeight
	return nil
}

// NewHTTPHandler returns an HTTP handler to serve proposervm API endpoints
func NewHTTPHandler(vm *VM) (http.Handler, error) {
	server := rpc.NewServer()
	server.RegisterCodec(json.NewCodec(), "application/json")
	server.RegisterCodec(json.NewCodec(), "application/json;charset=UTF-8")

	service := &Service{vm: vm}
	return server, server.RegisterService(service, "proposervm")
}

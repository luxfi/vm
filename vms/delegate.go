// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package vms

import (
	"context"
	"net/http"
)

// HandlerProvider is the interface that VMs must implement to provide HTTP handlers
type HandlerProvider interface {
	CreateHandlers(context.Context) (map[string]http.Handler, error)
}

// HandlerDelegator wraps a VM and delegates handler creation
type HandlerDelegator[T any] struct {
	vm T
}

// NewHandlerDelegator creates a new handler delegator for a VM
func NewHandlerDelegator[T any](vm T) *HandlerDelegator[T] {
	return &HandlerDelegator[T]{vm: vm}
}

// CreateHandlers delegates to the underlying VM's CreateHandlers method if it exists
func (h *HandlerDelegator[T]) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return DelegateHandlers(ctx, h.vm)
}

// CreateStaticHandlers returns an empty map as a default implementation
func (h *HandlerDelegator[T]) CreateStaticHandlers(ctx context.Context) (map[string]http.Handler, error) {
	// Default implementation returns no static handlers
	return nil, nil
}

// DelegateHandlers delegates the CreateHandlers call to the underlying VM
func DelegateHandlers(ctx context.Context, vm interface{}) (map[string]http.Handler, error) {
	if handlerCreator, ok := vm.(HandlerProvider); ok {
		return handlerCreator.CreateHandlers(ctx)
	}
	return nil, nil
}

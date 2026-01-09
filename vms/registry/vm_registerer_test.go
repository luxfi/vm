// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package registry

import (
	"context"
	"net/http"
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/mock/gomock"

	"github.com/luxfi/constants"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/vm/api/server"
	"github.com/luxfi/vm/vms/vmsmock"
)

var id = ids.GenerateTestID()

// Register should succeed even if we can't register a VM
func TestRegisterRegisterVMFails(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)

	// We fail to register the VM
	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(errTest)

	err := resources.registerer.Register(context.Background(), id, vmFactory)
	require.ErrorIs(t, err, errTest)
}

// Tests Register if a VM doesn't actually implement VM.
func TestRegisterBadVM(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)
	vm := "this is not a vm..."

	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(nil)
	// Since this factory produces a bad vm, we should get an error.
	vmFactory.EXPECT().New(gomock.Any()).Times(1).Return(vm, nil)

	err := resources.registerer.Register(context.Background(), id, vmFactory)
	require.ErrorIs(t, err, errNotVM)
}

// Tests Register if creating endpoints for a VM fails + shutdown fails
func TestRegisterCreateHandlersAndShutdownFails(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)
	vm := newTestVM()

	// Set up the manual mock behaviors
	vm.createHandlersF = func(context.Context) (map[string]http.Handler, error) {
		return nil, errTest
	}
	vm.shutdownF = func(context.Context) error {
		return errTest
	}

	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(nil)
	vmFactory.EXPECT().New(gomock.Any()).Times(1).Return(vm, nil)

	err := resources.registerer.Register(context.Background(), id, vmFactory)
	require.ErrorIs(t, err, errTest)
}

// Tests Register if creating endpoints for a VM fails + shutdown succeeds
func TestRegisterCreateHandlersFails(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)
	vm := newTestVM()

	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(nil)
	vmFactory.EXPECT().New(gomock.Any()).Times(1).Return(vm, nil)
	// We fail to create handlers + but succeed our shutdown
	// Set up the manual mock behaviors
	vm.createHandlersF = func(context.Context) (map[string]http.Handler, error) {
		return nil, errTest
	}
	vm.shutdownF = func(context.Context) error {
		return nil
	}

	err := resources.registerer.Register(context.Background(), id, vmFactory)
	require.ErrorIs(t, err, errTest)
}

// Tests Register if we fail to register the new endpoint on the server.
func TestRegisterAddRouteFails(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)
	vm := newTestVM()

	handlers := map[string]http.Handler{
		"foo": nil,
	}

	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(nil)
	vmFactory.EXPECT().New(gomock.Any()).Times(1).Return(vm, nil)
	// Set up the manual mock behaviors
	vm.createHandlersF = func(context.Context) (map[string]http.Handler, error) {
		return handlers, nil
	}
	// We fail to create an endpoint for the handler
	resources.mockServer.EXPECT().
		AddRoute(
			handlers["foo"],
			path.Join(constants.VMAliasPrefix, id.String()),
			"foo",
		).
		Times(1).
		Return(errTest)

	err := resources.registerer.Register(context.Background(), id, vmFactory)
	require.ErrorIs(t, err, errTest)
}

// Tests Register we can't find the alias for the newly registered vm
func TestRegisterAliasLookupFails(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)
	vm := newTestVM()

	handlers := map[string]http.Handler{
		"foo": nil,
	}

	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(nil)
	vmFactory.EXPECT().New(gomock.Any()).Times(1).Return(vm, nil)
	// Set up the manual mock behaviors
	vm.createHandlersF = func(context.Context) (map[string]http.Handler, error) {
		return handlers, nil
	}
	// Registering the route fails
	resources.mockServer.EXPECT().
		AddRoute(
			handlers["foo"],
			path.Join(constants.VMAliasPrefix, id.String()),
			"foo",
		).
		Times(1).
		Return(nil)
	resources.mockManager.EXPECT().Aliases(id).Times(1).Return(nil, errTest)

	err := resources.registerer.Register(context.Background(), id, vmFactory)
	require.ErrorIs(t, err, errTest)
}

// Tests Register if adding aliases for the newly registered vm fails
func TestRegisterAddAliasesFails(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)
	vm := newTestVM()

	handlers := map[string]http.Handler{
		"foo": nil,
	}
	aliases := []string{"alias-1", "alias-2"}

	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(nil)
	vmFactory.EXPECT().New(gomock.Any()).Times(1).Return(vm, nil)
	// Set up the manual mock behaviors
	vm.createHandlersF = func(context.Context) (map[string]http.Handler, error) {
		return handlers, nil
	}
	resources.mockServer.EXPECT().
		AddRoute(
			handlers["foo"],
			path.Join(constants.VMAliasPrefix, id.String()),
			"foo",
		).
		Times(1).
		Return(nil)
	resources.mockManager.EXPECT().Aliases(id).Times(1).Return(aliases, nil)
	// Adding aliases fails
	resources.mockServer.EXPECT().
		AddAliases(
			path.Join(constants.VMAliasPrefix, id.String()),
			path.Join(constants.VMAliasPrefix, aliases[0]),
			path.Join(constants.VMAliasPrefix, aliases[1]),
		).
		Return(errTest)

	err := resources.registerer.Register(context.Background(), id, vmFactory)
	require.ErrorIs(t, err, errTest)
}

// Tests Register if no errors are thrown
func TestRegisterHappyCase(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)
	vm := newTestVM()

	handlers := map[string]http.Handler{
		"foo": nil,
	}
	aliases := []string{"alias-1", "alias-2"}

	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(nil)
	vmFactory.EXPECT().New(gomock.Any()).Times(1).Return(vm, nil)
	// Set up the manual mock behaviors
	vm.createHandlersF = func(context.Context) (map[string]http.Handler, error) {
		return handlers, nil
	}
	resources.mockServer.EXPECT().
		AddRoute(
			handlers["foo"],
			path.Join(constants.VMAliasPrefix, id.String()),
			"foo",
		).
		Times(1).
		Return(nil)
	resources.mockManager.EXPECT().Aliases(id).Times(1).Return(aliases, nil)
	resources.mockServer.EXPECT().
		AddAliases(
			path.Join(constants.VMAliasPrefix, id.String()),
			path.Join(constants.VMAliasPrefix, aliases[0]),
			path.Join(constants.VMAliasPrefix, aliases[1]),
		).
		Times(1).
		Return(nil)

	require.NoError(t, resources.registerer.Register(context.Background(), id, vmFactory))
}

// RegisterWithReadLock should succeed even if we can't register a VM
func TestRegisterWithReadLockRegisterVMFails(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)

	// We fail to register the VM
	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(errTest)

	err := resources.registerer.RegisterWithReadLock(context.Background(), id, vmFactory)
	require.ErrorIs(t, err, errTest)
}

// Tests RegisterWithReadLock if a VM doesn't actually implement VM.
func TestRegisterWithReadLockBadVM(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)
	vm := "this is not a vm..."

	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(nil)
	// Since this factory produces a bad vm, we should get an error.
	vmFactory.EXPECT().New(gomock.Any()).Times(1).Return(vm, nil)

	err := resources.registerer.RegisterWithReadLock(context.Background(), id, vmFactory)
	require.ErrorIs(t, err, errNotVM)
}

// Tests RegisterWithReadLock if creating endpoints for a VM fails + shutdown fails
func TestRegisterWithReadLockCreateHandlersAndShutdownFails(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)
	vm := newTestVM()

	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(nil)
	vmFactory.EXPECT().New(gomock.Any()).Times(1).Return(vm, nil)
	// We fail to create handlers + fail to shutdown
	// Set up the manual mock behaviors
	vm.createHandlersF = func(context.Context) (map[string]http.Handler, error) {
		return nil, errTest
	}
	vm.shutdownF = func(context.Context) error {
		return errTest
	}

	err := resources.registerer.RegisterWithReadLock(context.Background(), id, vmFactory)
	require.ErrorIs(t, err, errTest)
}

// Tests RegisterWithReadLock if creating endpoints for a VM fails + shutdown succeeds
func TestRegisterWithReadLockCreateHandlersFails(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)
	vm := newTestVM()

	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(nil)
	vmFactory.EXPECT().New(gomock.Any()).Times(1).Return(vm, nil)
	// We fail to create handlers + but succeed our shutdown
	// Set up the manual mock behaviors
	vm.createHandlersF = func(context.Context) (map[string]http.Handler, error) {
		return nil, errTest
	}
	vm.shutdownF = func(context.Context) error {
		return nil
	}

	err := resources.registerer.RegisterWithReadLock(context.Background(), id, vmFactory)
	require.ErrorIs(t, err, errTest)
}

// Tests RegisterWithReadLock if we fail to register the new endpoint on the server.
func TestRegisterWithReadLockAddRouteWithReadLockFails(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)
	vm := newTestVM()

	handlers := map[string]http.Handler{
		"foo": nil,
	}

	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(nil)
	vmFactory.EXPECT().New(gomock.Any()).Times(1).Return(vm, nil)
	// Set up the manual mock behaviors
	vm.createHandlersF = func(context.Context) (map[string]http.Handler, error) {
		return handlers, nil
	}
	// We fail to create an endpoint for the handler
	resources.mockServer.EXPECT().
		AddRouteWithReadLock(
			handlers["foo"],
			path.Join(constants.VMAliasPrefix, id.String()),
			"foo",
		).
		Times(1).
		Return(errTest)

	err := resources.registerer.RegisterWithReadLock(context.Background(), id, vmFactory)
	require.ErrorIs(t, err, errTest)
}

// Tests RegisterWithReadLock we can't find the alias for the newly registered vm
func TestRegisterWithReadLockAliasLookupFails(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)
	vm := newTestVM()

	handlers := map[string]http.Handler{
		"foo": nil,
	}

	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(nil)
	vmFactory.EXPECT().New(gomock.Any()).Times(1).Return(vm, nil)
	// Set up the manual mock behaviors
	vm.createHandlersF = func(context.Context) (map[string]http.Handler, error) {
		return handlers, nil
	}
	// RegisterWithReadLocking the route fails
	resources.mockServer.EXPECT().
		AddRouteWithReadLock(
			handlers["foo"],
			path.Join(constants.VMAliasPrefix, id.String()),
			"foo",
		).
		Times(1).
		Return(nil)
	resources.mockManager.EXPECT().Aliases(id).Times(1).Return(nil, errTest)

	err := resources.registerer.RegisterWithReadLock(context.Background(), id, vmFactory)
	require.ErrorIs(t, err, errTest)
}

// Tests RegisterWithReadLock if adding aliases for the newly registered vm fails
func TestRegisterWithReadLockAddAliasesFails(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)
	vm := newTestVM()

	handlers := map[string]http.Handler{
		"foo": nil,
	}
	aliases := []string{"alias-1", "alias-2"}

	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(nil)
	vmFactory.EXPECT().New(gomock.Any()).Times(1).Return(vm, nil)
	// Set up the manual mock behaviors
	vm.createHandlersF = func(context.Context) (map[string]http.Handler, error) {
		return handlers, nil
	}
	resources.mockServer.EXPECT().
		AddRouteWithReadLock(
			handlers["foo"],
			path.Join(constants.VMAliasPrefix, id.String()),
			"foo",
		).
		Times(1).
		Return(nil)
	resources.mockManager.EXPECT().Aliases(id).Times(1).Return(aliases, nil)
	// Adding aliases fails
	resources.mockServer.EXPECT().
		AddAliasesWithReadLock(
			path.Join(constants.VMAliasPrefix, id.String()),
			path.Join(constants.VMAliasPrefix, aliases[0]),
			path.Join(constants.VMAliasPrefix, aliases[1]),
		).
		Return(errTest)

	err := resources.registerer.RegisterWithReadLock(context.Background(), id, vmFactory)
	require.ErrorIs(t, err, errTest)
}

// Tests RegisterWithReadLock if no errors are thrown
func TestRegisterWithReadLockHappyCase(t *testing.T) {
	resources := initRegistererTest(t)

	vmFactory := vmsmock.NewFactory(resources.ctrl)
	vm := newTestVM()

	handlers := map[string]http.Handler{
		"foo": nil,
	}
	aliases := []string{"alias-1", "alias-2"}

	resources.mockManager.EXPECT().RegisterFactory(gomock.Any(), id, vmFactory).Times(1).Return(nil)
	vmFactory.EXPECT().New(gomock.Any()).Times(1).Return(vm, nil)
	// Set up the manual mock behaviors
	vm.createHandlersF = func(context.Context) (map[string]http.Handler, error) {
		return handlers, nil
	}
	resources.mockServer.EXPECT().
		AddRouteWithReadLock(
			handlers["foo"],
			path.Join(constants.VMAliasPrefix, id.String()),
			"foo",
		).
		Times(1).
		Return(nil)
	resources.mockManager.EXPECT().Aliases(id).Times(1).Return(aliases, nil)
	resources.mockServer.EXPECT().
		AddAliasesWithReadLock(
			path.Join(constants.VMAliasPrefix, id.String()),
			path.Join(constants.VMAliasPrefix, aliases[0]),
			path.Join(constants.VMAliasPrefix, aliases[1]),
		).
		Times(1).
		Return(nil)

	require.NoError(t, resources.registerer.RegisterWithReadLock(context.Background(), id, vmFactory))
}

type vmRegistererTestResources struct {
	ctrl        *gomock.Controller
	mockManager *vmsmock.Manager
	mockServer  *server.MockServer
	registerer  VMRegisterer
}

func initRegistererTest(t *testing.T) *vmRegistererTestResources {
	ctrl := gomock.NewController(t)

	mockManager := vmsmock.NewManager(ctrl)
	mockServer := server.NewMockServer(ctrl)
	registerer := NewVMRegisterer(VMRegistererConfig{
		APIServer:    mockServer,
		Log:          log.NewNoOpLogger(),
		VMFactoryLog: log.NewNoOpLogger(),
		VMManager:    mockManager,
	})

	return &vmRegistererTestResources{
		ctrl:        ctrl,
		mockManager: mockManager,
		mockServer:  mockServer,
		registerer:  registerer,
	}
}

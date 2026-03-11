# vm

## Overview

Go package for Lux blockchain virtual machines. Provides the core interfaces and implementations for VM communication with the Lux node.

## Package Information

- **Type**: go
- **Module**: github.com/luxfi/vm
- **Repository**: github.com/luxfi/vm

## Build System

### Transport Selection

The package supports two transport options for VM<->Node communication:

1. **ZAP (default)**: Zero-copy binary wire protocol for high performance
2. **gRPC (optional)**: Traditional gRPC for compatibility/testing

```bash
# Default build - ZAP only (production)
go build ./...

# With gRPC support - for testing/compatibility
go build -tags=grpc ./...
```

### Build Tag Architecture

The `grpc` build tag controls which transport is compiled:

| Package | Default (ZAP) | With `-tags=grpc` |
|---------|---------------|-------------------|
| rpc/grpcutils | excluded | included |
| rpc/ghttp/* | excluded | included |
| rpc/gruntime | excluded | included |
| rpc/gvalidators | excluded | included |
| rpc/messenger | excluded | included |
| rpc/chain | excluded | included |
| gkeystore | excluded | included |
| gsharedmemory | excluded | included |

**Factory Pattern**:
- `rpc/factory_zap.go` (`!grpc`) - Full ZAP-based plugin factory
- `rpc/factory_grpc.go` (`grpc`) - Full gRPC-based plugin factory

**VM Client**:
- `rpc/vm_client_zap.go` (`!grpc`) - ZAP-based VM client (ZAPClient + zapBlock)
- `rpc/vm_client.go` (`grpc`) - gRPC-based VM client

**Subprocess Bootstrap**:
- `rpc/runtime/subprocess/runtime_zap.go` (`!grpc`) - Binary handshake protocol
- `rpc/runtime/subprocess/runtime.go` (`grpc`) - gRPC handshake
- `rpc/runtime/subprocess/config.go` - Shared Config and Status types

### Sender Package

The `rpc/sender` package provides p2p.Sender implementations:

```go
// ZAP transport (always available)
s := sender.ZAP(zapConn)

// gRPC transport (requires -tags=grpc)
s := sender.GRPC(senderpb.NewSenderClient(grpcConn))
```

## Key Packages

### Core

- `chain/` - ChainVM interface and implementations
- `components/` - Shared components (chain state, messages)
- `manager/` - VM factory and management

### RPC Layer

- `rpc/` - VM<->Node communication
  - `sender/` - p2p.Sender implementations (ZAP + gRPC)
  - `grpcutils/` - gRPC utilities (excluded by default)
  - `runtime/` - VM runtime management

### Storage

- `internal/database/rpcdb/` - Remote database client

### Proto

- `proto/pb/` - Generated protobuf messages
  - `sender/` - Sender service definitions

## Development

### Prerequisites

- Go 1.21+

### Build

```bash
# Production build (ZAP only)
go build ./...

# Development build with gRPC
go build -tags=grpc ./...
```

### Test

```bash
# Run tests (default transport)
go test -v ./...

# Run tests with gRPC
go test -tags=grpc -v ./...
```

### Verify Build Separation

```bash
# Check gRPC deps in ZAP build
go list -deps ./rpc | grep grpc  # Should be empty

# Check gRPC deps in gRPC build
go list -tags=grpc -deps ./rpc | grep grpc  # Should show ~62 deps
```

## ZAP Wire Protocol

The ZAP (Zero-copy App Proto) transport uses a binary wire protocol from `github.com/luxfi/api/zap`:

### Handshake Protocol

```
VM → Node:
  [4 bytes: length][4 bytes: protocol version][vm addr string]
Node → VM:
  [1 byte: ACK (0x01)]
```

### Message Format

```
[4 bytes: length][1 byte: message type][payload...]

Message types (zapwire.Msg*):
- MsgInitialize, MsgShutdown, MsgSetState
- MsgBuildBlock, MsgParseBlock, MsgGetBlock
- MsgBlockVerify, MsgBlockAccept, MsgBlockReject
- MsgVersion, MsgHealth, etc.
```

### Key Types

```go
// State constants
zapwire.StateStateSyncing
zapwire.StateBootstrapping
zapwire.StateNormalOp

// Error constants
zapwire.ErrorClosed    → database.ErrClosed
zapwire.ErrorNotFound  → database.ErrNotFound
```

## Integration with Lux Ecosystem

This package is part of the Lux blockchain ecosystem:
- GitHub: https://github.com/luxfi
- Docs: https://docs.lux.network

---

*Last updated: 2026-01-24*

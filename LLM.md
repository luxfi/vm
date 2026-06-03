# vm

## Overview

Go package for Lux blockchain virtual machines. Provides the core interfaces and implementations for VM communication with the Lux node.

## Package Information

- **Type**: go
- **Module**: github.com/luxfi/vm
- **Repository**: github.com/luxfi/vm

## Build System

### Transport Selection

The package uses ZAP-native (LP-200) as the ONLY transport for VM<->Node
communication. The historical gRPC fallback (and `-tags=grpc` opt-in) was
retired in v1.26.31; ZAP is the canonical and exclusive wire protocol.

```bash
# Build — ZAP only, no build tags
go build ./...
```

**Factory Pattern**:
- `rpc/factory_zap.go` — ZAP-based plugin factory (the only factory)

**VM Client**:
- `rpc/vm_client_zap.go` — ZAP-based VM client (ZAPClient + zapBlock)

**Subprocess Bootstrap**:
- `rpc/runtime/subprocess/runtime_zap.go` — Binary handshake protocol
- `rpc/runtime/subprocess/config.go` — Shared Config and Status types

### Sender Package

The `rpc/sender` package provides p2p.Sender implementations:

```go
// ZAP transport (the only transport)
s := sender.ZAP(zapConn)
```

## Key Packages

### Core

- `chain/` - ChainVM interface and implementations
- `components/` - Shared components (chain state, messages)
- `manager/` - VM factory and management

### RPC Layer

- `rpc/` - VM<->Node communication
  - `sender/` - p2p.Sender implementations (ZAP-native, LP-200)
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
# Build (ZAP only — no build tags exist)
go build ./...
```

### Test

```bash
# Run tests
go test -v ./...
```

### Verify Zero gRPC

```bash
# Confirm zero gRPC in the dep graph
go list -deps ./rpc | grep grpc  # Must be empty
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

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

### State sync

Six messages carry `chain.StateSyncableVM` across the boundary:
`MsgStateSyncEnabled`, `MsgGetOngoingSyncStateSummary`, `MsgGetLastStateSummary`,
`MsgParseStateSummary`, `MsgGetStateSummary`, `MsgStateSummaryAccept`.

`newZAPVMServer` probes the wrapped VM for the surface once, the same way it
probes for Quasar export. A VM without it answers `ErrorStateSyncNotImplemented`
on all six, so a node knows to bootstrap that chain block by block.

Accept is the asymmetric one. A summary is an object on the plugin side and only
its id crosses, so the server records every summary it hands out and resolves
`MsgStateSummaryAccept` against that map. An id the server never produced is
refused — rebuilding one from caller-supplied bytes would accept a state the
network never ratified. The map is cleared on a successful accept (the sync that
starts supersedes every other candidate) and capped at `maxSummaries`.

### Key Types

```go
// State constants
zapwire.StateStateSyncing
zapwire.StateBootstrapping
zapwire.StateNormalOp

// Error constants — ErrorUnspecified is SUCCESS, never a failure's fallback
zapwire.ErrorClosed                  → database.ErrClosed
zapwire.ErrorNotFound                → database.ErrNotFound
zapwire.ErrorStateSyncNotImplemented → block.ErrStateSyncableVMNotImplemented
zapwire.ErrorInternal                → anything else
```

## Integration with Lux Ecosystem

This package is part of the Lux blockchain ecosystem:
- GitHub: https://github.com/luxfi
- Docs: https://docs.lux.network

---

*Last updated: 2026-01-24*

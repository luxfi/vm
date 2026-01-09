# Consensus Package

This package provides consensus infrastructure for the Lux node.

## Overview

The consensus package contains:

- **Acceptor**: Callback mechanism for accepted blocks/vertices
- **Quasar**: Hybrid quantum-safe finality engine (BLS + Ringtail)
- **Engine**: Chain and DAG consensus engine interfaces

## Vote Terminology

This package uses "Vote" as the semantic name for validator responses to block proposals.

**Vote (wire format: Chits)**: A validator's agreement or preference for a specific block. On the network wire, votes are transmitted using the "Chits" message format for backwards compatibility with existing protocols.

```go
// VoteMessage represents a vote for a specific block.
// This is a semantic wrapper - the wire format remains Chits.
type VoteMessage struct {
    BlockID   ids.ID
    RequestID uint32
}
```

The `UnsolicitedVoteRequestID` constant (value 0) indicates a vote sent without a prior request, used in fast-follow scenarios.

## Package Structure

```
consensus/
  acceptor.go     # Acceptor interface and group management
  engine/
    chain/
      vote.go     # Vote message types (wire format: Chits)
  quasar/
    quasar.go     # Hybrid BLS + Ringtail finality
    types.go      # Signature types and interfaces
    config.go     # Configuration
    gpu_ntt.go    # GPU acceleration for NTT operations
```

## Acceptor

The `Acceptor` interface is called before containers are committed as accepted:

```go
type Acceptor interface {
    Accept(ctx *consensuscontext.Context, containerID ids.ID, container []byte) error
}
```

Multiple acceptors can be registered per chain via `AcceptorGroup`.

## Quasar Consensus

Quasar provides hybrid quantum-safe finality by combining:

1. **BLS Aggregate Signatures** - Fast classical signatures (96 bytes)
2. **Ringtail Threshold Signatures** - Post-quantum threshold signatures (t-of-n)

Both signature paths run in parallel, and blocks achieve finality only when both complete with sufficient weight.

See `quasar/README.md` for detailed documentation.

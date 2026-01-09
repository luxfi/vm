# Consensus Package - Session Notes

## Terminology Update (2026-01-04)

Updated documentation to use "Vote" terminology consistently:

- **Vote**: Semantic name for validator responses to block proposals
- **Chits**: Wire protocol format (preserved for backwards compatibility)

Note: "Vote (wire format: Chits)" should be used where clarification is needed.

## Package Contents

### acceptor.go

Provides `Acceptor` interface for block acceptance callbacks:
- `Accept()` called before container committed as accepted
- `AcceptorGroup` manages multiple acceptors per chain
- Thread-safe with RWMutex

### engine/chain/vote.go

Vote message types for consensus:
- `VoteMessage` - Vote for specific block (wire format: Chits)
- `UnsolicitedVoteRequestID` - Constant for fast-follow votes

### quasar/

Hybrid quantum-safe finality engine:
- `Quasar` - Main consensus coordinator
- `RingtailCoordinator` - Post-quantum threshold signatures
- `RingtailSignature`, `BLSSignature`, `QuasarSignature` - Signature types

## Architecture Notes

### Dual-Path Finality

```
Block arrives
    |
    +-- BLS PATH (fast) --------+-- RINGTAIL PATH (quantum-safe) --+
    |   All validators sign     |   Round 1: commitments           |
    |   with BLS keys           |   Round 2: partial signatures    |
    |   Aggregate (96 bytes)    |   Combine threshold signature    |
    |                           |                                  |
    +---------------------------+----------------------------------+
                                |
                         HYBRID PROOF
                    (BLS + Ringtail combined)
                                |
                        QUANTUM FINALITY
```

### Vote Flow

1. Block proposed via gossip
2. Validators vote (wire: Chits message)
3. Votes collected and aggregated
4. Quorum check (2/3+ weight)
5. Finality achieved when both BLS and Ringtail complete

## Test Coverage

- `quasar/config_test.go` - Configuration tests
- `quasar/integration_test.go` - Integration tests

## Recent Changes

- 2026-01-04: Created documentation files with Vote terminology

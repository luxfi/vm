// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

/*
Package consensus provides consensus infrastructure for the Lux node.

# Terminology

This package uses "Vote" as the semantic name for validator responses to
block proposals. On the network wire, votes are transmitted using the
"Chits" message format for backwards compatibility.

Vote (wire format: Chits): A validator's agreement or preference for a
specific block. The VoteMessage type wraps this semantic concept while
the underlying protocol uses Chits.

# Components

The package contains several components:

Acceptor: Callback interface invoked before blocks are committed as
accepted. Multiple acceptors can be registered per chain via AcceptorGroup.

Engine: Chain and DAG consensus engine interfaces located in the engine
subpackage. The chain/vote.go file defines vote message types.

Quasar: Hybrid quantum-safe finality engine combining BLS aggregate
signatures (classical) with Ringtail threshold signatures (post-quantum).
Located in the quasar subpackage.

# Quasar Consensus

The Quasar engine achieves hybrid finality by running two signature paths
in parallel:

  - BLS Path: Fast aggregate signatures from 2/3+ validators
  - Ringtail Path: Post-quantum threshold signatures (t-of-n)

Blocks achieve quantum finality only when both paths complete successfully.

See the quasar subpackage for detailed implementation.
*/
package consensus

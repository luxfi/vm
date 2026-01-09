// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

/*
Package quasar provides hybrid quantum-safe consensus finality.

# Overview

Quasar is the gravitational center of Lux consensus, binding P-Chain
(BLS signatures) and Q-Chain (Ringtail post-quantum threshold) into
unified hybrid finality across all Lux networks.

# Architecture

All validators maintain both keypairs:
  - BLS keypair: Aggregate signatures (classical, fast)
  - Ringtail keypair: Threshold signatures (post-quantum, 2-round)

Both signature paths run in parallel:

	Block arrives
	    |
	    +-- BLS PATH ----------+-- RINGTAIL PATH --------+
	    |   All validators     |   Round 1: commitments  |
	    |   sign with BLS      |   Round 2: partials     |
	    |   Aggregate (96B)    |   Combine threshold sig |
	    +----------------------+-------------------------+
	                           |
	                     HYBRID PROOF
	                  BLS + Ringtail combined
	                           |
	                   QUANTUM FINALITY

# Vote Flow

Validators cast votes (wire format: Chits) for proposed blocks. The
Quasar engine collects these votes and produces finality proofs when:
  - 2/3+ validator weight signed via BLS
  - t-of-n validators completed Ringtail threshold signing

# Signature Types

The package defines several signature types:
  - SignatureTypeBLS: Classical BLS signatures
  - SignatureTypeRingtail: Post-quantum threshold
  - SignatureTypeQuasar: Hybrid combining both
  - SignatureTypeMLDSA: ML-DSA fallback

# Components

Quasar: Main consensus hub coordinating both signature paths.

RingtailCoordinator: Manages the 2-round threshold signing protocol
for post-quantum security.

QuantumFinality: Represents a block that achieved hybrid finality with
both BLS and Ringtail proofs.
*/
package quasar

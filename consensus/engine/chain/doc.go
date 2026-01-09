// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

/*
Package chain provides chain consensus engine types and interfaces.

# Vote Terminology

This package uses "Vote" as the semantic name for validator responses.
Vote (wire format: Chits): The underlying network protocol transmits
votes using the Chits message format for backwards compatibility.

The VoteMessage type provides a semantic wrapper around the wire format:

	type VoteMessage struct {
	    BlockID   ids.ID
	    RequestID uint32
	}

UnsolicitedVoteRequestID (value 0) indicates a vote sent without a prior
request, used in fast-follow scenarios where a follower sends a vote back
to the proposer after accepting a gossiped block.
*/
package chain

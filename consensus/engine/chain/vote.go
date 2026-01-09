// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import "github.com/luxfi/ids"

// Vote constants for consensus message handling.
//
// Vote is the semantic name for a validator's response to a block proposal.
// On the wire, votes are transmitted using the "Vote" message format
// for backwards compatibility with existing network protocols.
const (
	// UnsolicitedVoteRequestID indicates a vote sent without a prior request.
	// This is used in fast-follow scenarios where a follower node sends
	// a vote back to the proposer after accepting a gossiped block.
	UnsolicitedVoteRequestID = uint32(0)
)

// VoteMessage represents a vote for a specific block.
// This is a semantic wrapper - the wire format remains Vote.
type VoteMessage struct {
	BlockID   ids.ID
	RequestID uint32
}

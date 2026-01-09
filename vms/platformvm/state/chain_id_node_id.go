// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package state

import (
	"fmt"

	"github.com/luxfi/ids"
)

// chainIDNodeID = [chainID] + [nodeID]
const chainIDNodeIDEntryLength = ids.IDLen + ids.NodeIDLen

var errUnexpectedChainIDNodeIDLength = fmt.Errorf("expected chainID+nodeID entry length %d", chainIDNodeIDEntryLength)

type chainIDNodeID struct {
	chainID ids.ID
	nodeID  ids.NodeID
}

func (s *chainIDNodeID) Marshal() []byte {
	data := make([]byte, chainIDNodeIDEntryLength)
	copy(data, s.chainID[:])
	copy(data[ids.IDLen:], s.nodeID[:])
	return data
}

func (s *chainIDNodeID) Unmarshal(data []byte) error {
	if len(data) != chainIDNodeIDEntryLength {
		return errUnexpectedChainIDNodeIDLength
	}

	copy(s.chainID[:], data)
	copy(s.nodeID[:], data[ids.IDLen:])
	return nil
}

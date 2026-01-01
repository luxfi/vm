// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

// Status represents the status of a block
type Status uint8

const (
	Unknown Status = iota
	Processing
	Rejected
	Accepted
)

// String returns the string representation of the status
func (s Status) String() string {
	switch s {
	case Unknown:
		return "Unknown"
	case Processing:
		return "Processing"
	case Rejected:
		return "Rejected"
	case Accepted:
		return "Accepted"
	default:
		return "Unknown"
	}
}

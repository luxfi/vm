// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package json

import (
	stdjson "encoding/json"
	"time"
)

// Time is an instant, on a wire whose fields are offsets.
//
// time.Time cannot be one. Its fields are all unexported, so a reply that holds
// one lays out with nothing in it — eight bytes pointing at an empty message —
// and a caller reads a zero it cannot tell from a zero that was sent. That is
// worse than a refusal: nothing fails and the value is simply absent.
//
// The same instant as three numbers does have a layout. The JSON is byte for
// byte what time.Time's own marshaler writes, because the offset is all the
// rendering depends on: RFC 3339 spells a zero offset "Z" and any other one
// "+HH:MM", so carrying it is enough to put the instant back in the zone it was
// read in.
type Time struct {
	// Seconds is seconds since the epoch.
	Seconds int64 `json:"seconds"`
	// Nanos is the nanosecond within that second.
	Nanos int32 `json:"nanos"`
	// Offset is seconds east of UTC.
	Offset int32 `json:"offset"`
}

// NewTime is the instant t, as a value that can cross.
func NewTime(t time.Time) Time {
	_, offset := t.Zone()
	return Time{Seconds: t.Unix(), Nanos: int32(t.Nanosecond()), Offset: int32(offset)}
}

// Time is the instant, in the zone it was read in.
func (t Time) Time() time.Time {
	return time.Unix(t.Seconds, int64(t.Nanos)).In(time.FixedZone("", int(t.Offset)))
}

func (t Time) MarshalJSON() ([]byte, error) {
	return stdjson.Marshal(t.Time())
}

func (t *Time) UnmarshalJSON(b []byte) error {
	if string(b) == Null {
		return nil
	}
	var parsed time.Time
	if err := stdjson.Unmarshal(b, &parsed); err != nil {
		return err
	}
	*t = NewTime(parsed)
	return nil
}

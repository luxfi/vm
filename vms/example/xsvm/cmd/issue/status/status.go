// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package status

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/vm/vms/example/xsvm/tx"
)

type TxIssuance struct {
	Tx        *tx.Tx
	TxID      ids.ID
	Nonce     uint64
	StartTime time.Time
}

func (s *TxIssuance) String() string {
	txJSON, err := json.MarshalIndent(s.Tx, "", "  ")
	if err != nil {
		return "failed to marshal transaction: " + err.Error()
	}
	return fmt.Sprintf("issued tx %s in %s\n%s\n", s.TxID, time.Since(s.StartTime), string(txJSON))
}

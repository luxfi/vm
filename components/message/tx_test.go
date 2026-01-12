// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package message

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/constants"
	"github.com/luxfi/utils"
)

func TestTx(t *testing.T) {
	require := require.New(t)

	tx := crypto.RandomBytes(256 * constants.KiB)
	builtMsg := Tx{
		Tx: tx,
	}
	builtMsgBytes, err := Build(&builtMsg)
	require.NoError(err)
	require.Equal(builtMsgBytes, builtMsg.Bytes())

	parsedMsgIntf, err := Parse(builtMsgBytes)
	require.NoError(err)
	require.Equal(builtMsgBytes, parsedMsgIntf.Bytes())

	require.IsType(&Tx{}, parsedMsgIntf)
	parsedMsg := parsedMsgIntf.(*Tx)

	require.Equal(tx, parsedMsg.Tx)
}

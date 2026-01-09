// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package block

import (
	"crypto"
	"crypto/rand"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/staking"
	"github.com/luxfi/crypto/hash"
	"github.com/luxfi/utils/wrappers"
)

func BuildUnsigned(
	parentID ids.ID,
	timestamp time.Time,
	pChainHeight uint64,
	epoch Epoch,
	blockBytes []byte,
) (SignedBlock, error) {
	var block SignedBlock = &statelessBlock{
		StatelessBlock: statelessUnsignedBlock{
			ParentID:     parentID,
			Timestamp:    timestamp.Unix(),
			PChainHeight: pChainHeight,
			Epoch:        epoch,
			Certificate:  nil,
			Block:        blockBytes,
		},
		timestamp: timestamp,
	}

	bytes, err := Codec.Marshal(CodecVersion, &block)
	if err != nil {
		return nil, err
	}

	return block, block.initialize(bytes)
}

func Build(
	parentID ids.ID,
	timestamp time.Time,
	pChainHeight uint64,
	epoch Epoch,
	cert *staking.Certificate,
	blockBytes []byte,
	chainID ids.ID,
	key crypto.Signer,
) (SignedBlock, error) {
	block := &statelessBlock{
		StatelessBlock: statelessUnsignedBlock{
			ParentID:     parentID,
			Timestamp:    timestamp.Unix(),
			PChainHeight: pChainHeight,
			Epoch:        epoch,
			Certificate:  cert.Raw,
			Block:        blockBytes,
		},
		timestamp: timestamp,
		cert:      cert,
		proposer: ids.NodeIDFromCert(&ids.Certificate{
			Raw:       cert.Raw,
			PublicKey: cert.PublicKey,
		}),
	}
	var blockIntf SignedBlock = block

	unsignedBytesWithEmptySignature, err := Codec.Marshal(CodecVersion, &blockIntf)
	if err != nil {
		return nil, err
	}

	// The serialized form of the block is the unsignedBytes followed by the
	// signature, which is prefixed by a uint32. Because we are marshalling the
	// block with an empty signature, we only need to strip off the length
	// prefix to get the unsigned bytes.
	lenUnsignedBytes := len(unsignedBytesWithEmptySignature) - wrappers.IntLen
	unsignedBytes := unsignedBytesWithEmptySignature[:lenUnsignedBytes]
	block.id = hash.ComputeHash256Array(unsignedBytes)

	header, err := BuildHeader(chainID, parentID, block.id)
	if err != nil {
		return nil, err
	}

	headerHash := hash.ComputeHash256(header.Bytes())
	block.Signature, err = key.Sign(rand.Reader, headerHash, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	block.bytes, err = Codec.Marshal(CodecVersion, &blockIntf)
	return block, err
}

func BuildHeader(
	chainID ids.ID,
	parentID ids.ID,
	bodyID ids.ID,
) (Header, error) {
	header := statelessHeader{
		Chain:  chainID,
		Parent: parentID,
		Body:   bodyID,
	}

	bytes, err := Codec.Marshal(CodecVersion, &header)
	header.bytes = bytes
	return &header, err
}

// BuildOption the option block
// [parentID] is the ID of this option's wrapper parent block
// [innerBytes] is the byte representation of a child option block
func BuildOption(
	parentID ids.ID,
	innerBytes []byte,
) (Block, error) {
	var block Block = &option{
		PrntID:     parentID,
		InnerBytes: innerBytes,
	}

	bytes, err := Codec.Marshal(CodecVersion, &block)
	if err != nil {
		return nil, err
	}

	return block, block.initialize(bytes)
}

// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package network

import (
	"context"
	"fmt"
	"math"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/p2p"
	"github.com/luxfi/vm/proto/pb/platformvm"
	"github.com/luxfi/vm/vms/platformvm/state"
	"github.com/luxfi/vm/vms/platformvm/warp/message"
	"github.com/luxfi/vm/vms/platformvm/warp/payload"
	"github.com/luxfi/warp"
)

const (
	ErrFailedToParseWarpAddressedCall = iota + 1
	ErrWarpAddressedCallHasSourceAddress
	ErrFailedToParseWarpAddressedCallPayload
	ErrUnsupportedWarpAddressedCallPayloadType

	ErrFailedToParseJustification
	ErrConversionDoesNotExist
	ErrMismatchedConversionID

	ErrInvalidJustificationType
	ErrFailedToParseNetID
	ErrMismatchedValidationID
	ErrValidationDoesNotExist
	ErrValidationExists
	ErrFailedToParseRegisterL1Validator
	ErrValidationCouldBeRegistered

	ErrImpossibleNonce
	ErrWrongNonce
	ErrWrongWeight
)

var _ warp.Verifier = (*signatureRequestVerifier)(nil)

type signatureRequestVerifier struct {
	stateLock sync.Locker
	state     state.Chain
}

func (s signatureRequestVerifier) Verify(
	_ context.Context,
	unsignedMessage *warp.UnsignedMessage,
	justification []byte,
) error {
	msg, err := payload.ParseAddressedCall(unsignedMessage.Payload)
	if err != nil {
		return &p2p.Error{
			Code:    ErrFailedToParseWarpAddressedCall,
			Message: "failed to parse warp addressed call: " + err.Error(),
		}
	}
	if len(msg.SourceAddress) != 0 {
		return &p2p.Error{
			Code:    ErrWarpAddressedCallHasSourceAddress,
			Message: "source address should be empty",
		}
	}

	payloadIntf, err := message.Parse(msg.Payload)
	if err != nil {
		return &p2p.Error{
			Code:    ErrFailedToParseWarpAddressedCallPayload,
			Message: "failed to parse warp addressed call payload: " + err.Error(),
		}
	}

	switch payload := payloadIntf.(type) {
	case *message.ChainToL1Conversion:
		return s.verifyChainToL1Conversion(payload, justification)
	case *message.L1ValidatorRegistration:
		return s.verifyL1ValidatorRegistration(payload, justification)
	case *message.L1ValidatorWeight:
		return s.verifyL1ValidatorWeight(payload)
	default:
		return &p2p.Error{
			Code:    ErrUnsupportedWarpAddressedCallPayloadType,
			Message: fmt.Sprintf("unsupported warp addressed call payload type: %T", payloadIntf),
		}
	}
}

func (s signatureRequestVerifier) verifyChainToL1Conversion(
	msg *message.ChainToL1Conversion,
	justification []byte,
) error {
	chainID, err := ids.ToID(justification)
	if err != nil {
		return &p2p.Error{
			Code:    ErrFailedToParseJustification,
			Message: "failed to parse chainID justification: " + err.Error(),
		}
	}

	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	conversion, err := s.state.GetNetToL1Conversion(chainID)
	if err == database.ErrNotFound {
		return &p2p.Error{
			Code:    ErrConversionDoesNotExist,
			Message: fmt.Sprintf("chain %q has not been converted", chainID),
		}
	}
	if err != nil {
		return &p2p.Error{
			Code:    0,
			Message: "failed to get chain conversionID: " + err.Error(),
		}
	}

	if msg.ID != conversion.ConversionID {
		return &p2p.Error{
			Code:    ErrMismatchedConversionID,
			Message: fmt.Sprintf("provided conversionID %q != expected conversionID %q", msg.ID, conversion.ConversionID),
		}
	}

	return nil
}

func (s signatureRequestVerifier) verifyL1ValidatorRegistration(
	msg *message.L1ValidatorRegistration,
	justificationBytes []byte,
) error {
	if msg.Registered {
		return s.verifyL1ValidatorRegistered(msg.ValidationID)
	}

	var justification platformvm.L1ValidatorRegistrationJustification
	if err := proto.Unmarshal(justificationBytes, &justification); err != nil {
		return &p2p.Error{
			Code:    ErrFailedToParseJustification,
			Message: "failed to parse justification: " + err.Error(),
		}
	}

	switch preimage := justification.GetPreimage().(type) {
	case *platformvm.L1ValidatorRegistrationJustification_ConvertChainToL1TxData:
		return s.verifyValidatorNotCurrentlyRegistered(msg.ValidationID, preimage.ConvertChainToL1TxData)
	case *platformvm.L1ValidatorRegistrationJustification_RegisterL1ValidatorMessage:
		return s.verifyValidatorCanNotValidate(msg.ValidationID, preimage.RegisterL1ValidatorMessage)
	default:
		return &p2p.Error{
			Code:    ErrInvalidJustificationType,
			Message: fmt.Sprintf("invalid justification type: %T", justification.Preimage),
		}
	}
}

// verifyL1ValidatorRegistered verifies that the validationID is currently a
// validator.
func (s signatureRequestVerifier) verifyL1ValidatorRegistered(
	validationID ids.ID,
) error {
	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	// Verify that the validator exists
	_, err := s.state.GetL1Validator(validationID)
	if err == database.ErrNotFound {
		return &p2p.Error{
			Code:    ErrValidationDoesNotExist,
			Message: fmt.Sprintf("validation %q does not exist", validationID),
		}
	}
	if err != nil {
		return &p2p.Error{
			Code:    0,
			Message: "failed to get L1 validator: " + err.Error(),
		}
	}
	return nil
}

// verifyValidatorNotCurrentlyRegistered verifies that the validationID
// could only correspond to a validator from a ConvertChainToL1Tx and that it
// is not currently a validator.
func (s signatureRequestVerifier) verifyValidatorNotCurrentlyRegistered(
	validationID ids.ID,
	justification *platformvm.ChainIDIndex,
) error {
	chainID, err := ids.ToID(justification.GetChainId())
	if err != nil {
		return &p2p.Error{
			Code:    ErrFailedToParseNetID,
			Message: "failed to parse chainID: " + err.Error(),
		}
	}

	justificationID := chainID.Append(justification.GetIndex())
	if validationID != justificationID {
		return &p2p.Error{
			Code:    ErrMismatchedValidationID,
			Message: fmt.Sprintf("validationID %q != justificationID %q", validationID, justificationID),
		}
	}

	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	// Verify that the provided chainID has been converted.
	_, err = s.state.GetNetToL1Conversion(chainID)
	if err == database.ErrNotFound {
		return &p2p.Error{
			Code:    ErrConversionDoesNotExist,
			Message: fmt.Sprintf("chain %q has not been converted", chainID),
		}
	}
	if err != nil {
		return &p2p.Error{
			Code:    0,
			Message: "failed to get chain conversionID: " + err.Error(),
		}
	}

	// Verify that the validator is not in the current state
	_, err = s.state.GetL1Validator(validationID)
	if err == nil {
		return &p2p.Error{
			Code:    ErrValidationExists,
			Message: fmt.Sprintf("validation %q exists", validationID),
		}
	}
	if err != database.ErrNotFound {
		return &p2p.Error{
			Code:    0,
			Message: "failed to lookup L1 validator: " + err.Error(),
		}
	}

	// Either the validator was removed or it was never registered as part of
	// the chain conversion.
	return nil
}

// verifyValidatorCanNotValidate verifies that the validationID is not
// currently and can never become a validator.
func (s signatureRequestVerifier) verifyValidatorCanNotValidate(
	validationID ids.ID,
	justificationBytes []byte,
) error {
	justification, err := message.ParseRegisterL1Validator(justificationBytes)
	if err != nil {
		return &p2p.Error{
			Code:    ErrFailedToParseRegisterL1Validator,
			Message: "failed to parse RegisterL1Validator justification: " + err.Error(),
		}
	}

	justificationID := justification.ValidationID()
	if validationID != justificationID {
		return &p2p.Error{
			Code:    ErrMismatchedValidationID,
			Message: fmt.Sprintf("validationID %q != justificationID %q", validationID, justificationID),
		}
	}

	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	// Verify that the validator does not currently exist
	_, err = s.state.GetL1Validator(validationID)
	if err == nil {
		return &p2p.Error{
			Code:    ErrValidationExists,
			Message: fmt.Sprintf("validation %q exists", validationID),
		}
	}
	if err != database.ErrNotFound {
		return &p2p.Error{
			Code:    0,
			Message: "failed to lookup L1 validator: " + err.Error(),
		}
	}

	currentTimeUnix := uint64(s.state.GetTimestamp().Unix())
	if justification.Expiry <= currentTimeUnix {
		return nil // The expiry time has passed
	}

	// If the validation ID was successfully registered and then removed, it can
	// never be re-used again even if its expiry has not yet passed.
	hasExpiry, err := s.state.HasExpiry(state.ExpiryEntry{
		Timestamp:    justification.Expiry,
		ValidationID: validationID,
	})
	if err != nil {
		return &p2p.Error{
			Code:    0,
			Message: "failed to lookup expiry: " + err.Error(),
		}
	}
	if !hasExpiry {
		return &p2p.Error{
			Code:    ErrValidationCouldBeRegistered,
			Message: fmt.Sprintf("validation %q can be registered until %d", validationID, justification.Expiry),
		}
	}

	return nil // The validator has been removed
}

func (s signatureRequestVerifier) verifyL1ValidatorWeight(
	msg *message.L1ValidatorWeight,
) error {
	if msg.Nonce == math.MaxUint64 {
		return &p2p.Error{
			Code:    ErrImpossibleNonce,
			Message: "impossible nonce",
		}
	}

	s.stateLock.Lock()
	defer s.stateLock.Unlock()

	l1Validator, err := s.state.GetL1Validator(msg.ValidationID)
	switch {
	case err == database.ErrNotFound:
		// If the peer is attempting to verify that the weight of the validator
		// is 0, they should be requesting a [message.L1ValidatorRegistration]
		// with Registered set to false.
		return &p2p.Error{
			Code:    ErrValidationDoesNotExist,
			Message: fmt.Sprintf("validation %q does not exist", msg.ValidationID),
		}
	case err != nil:
		return &p2p.Error{
			Code:    0,
			Message: "failed to get L1 validator: " + err.Error(),
		}
	case msg.Nonce+1 != l1Validator.MinNonce:
		return &p2p.Error{
			Code:    ErrWrongNonce,
			Message: fmt.Sprintf("provided nonce %d != expected nonce (%d - 1)", msg.Nonce, l1Validator.MinNonce),
		}
	case msg.Weight != l1Validator.Weight:
		return &p2p.Error{
			Code:    ErrWrongWeight,
			Message: fmt.Sprintf("provided weight %d != expected weight %d", msg.Weight, l1Validator.Weight),
		}
	default:
		return nil // The nonce and weight are correct
	}
}

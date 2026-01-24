// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sender

import (
	"context"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
	"github.com/luxfi/p2p"
)

var _ SenderServer = (*ZAPServer)(nil)

// ZAPServer handles incoming ZAP sender messages and forwards them to p2p.Sender
type ZAPServer struct {
	sender p2p.Sender
}

// NewZAPServer returns a ZAP server that wraps a p2p.Sender
func NewZAPServer(sender p2p.Sender) *ZAPServer {
	return &ZAPServer{sender: sender}
}

// GRPCRegistrar returns nil since this is a ZAP server.
func (s *ZAPServer) GRPCRegistrar() interface{} {
	return nil
}

// ZAPHandler returns this server as the ZAP handler.
func (s *ZAPServer) ZAPHandler() ZAPHandler {
	return s
}

// HandleSendRequest handles a SendRequest message
func (s *ZAPServer) HandleSendRequest(ctx context.Context, payload []byte) error {
	msg := &zapwire.SendRequestMsg{}
	r := zapwire.NewReader(payload)
	if err := msg.Decode(r); err != nil {
		return err
	}

	nodeIDs := set.NewSet[ids.NodeID](len(msg.NodeIDs))
	for _, nodeIDBytes := range msg.NodeIDs {
		nodeID, err := ids.ToNodeID(nodeIDBytes)
		if err != nil {
			return err
		}
		nodeIDs.Add(nodeID)
	}

	return s.sender.SendRequest(ctx, nodeIDs, msg.RequestID, msg.Request)
}

// HandleSendResponse handles a SendResponse message
func (s *ZAPServer) HandleSendResponse(ctx context.Context, payload []byte) error {
	msg := &zapwire.SendResponseMsg{}
	r := zapwire.NewReader(payload)
	if err := msg.Decode(r); err != nil {
		return err
	}

	nodeID, err := ids.ToNodeID(msg.NodeID)
	if err != nil {
		return err
	}

	return s.sender.SendResponse(ctx, nodeID, msg.RequestID, msg.Response)
}

// HandleSendError handles a SendError message
func (s *ZAPServer) HandleSendError(ctx context.Context, payload []byte) error {
	msg := &zapwire.SendErrorMsg{}
	r := zapwire.NewReader(payload)
	if err := msg.Decode(r); err != nil {
		return err
	}

	nodeID, err := ids.ToNodeID(msg.NodeID)
	if err != nil {
		return err
	}

	return s.sender.SendError(ctx, nodeID, msg.RequestID, msg.ErrorCode, msg.ErrorMessage)
}

// HandleSendGossip handles a SendGossip message
func (s *ZAPServer) HandleSendGossip(ctx context.Context, payload []byte) error {
	msg := &zapwire.SendGossipMsg{}
	r := zapwire.NewReader(payload)
	if err := msg.Decode(r); err != nil {
		return err
	}

	nodeIDs := set.NewSet[ids.NodeID](len(msg.NodeIDs))
	for _, nodeIDBytes := range msg.NodeIDs {
		nodeID, err := ids.ToNodeID(nodeIDBytes)
		if err != nil {
			return err
		}
		nodeIDs.Add(nodeID)
	}

	config := p2p.SendConfig{
		NodeIDs:       nodeIDs,
		Validators:    int(msg.Validators),
		NonValidators: int(msg.NonValidators),
		Peers:         int(msg.Peers),
	}

	return s.sender.SendGossip(ctx, config, msg.Msg)
}

// Handle routes a ZAP message to the appropriate handler
func (s *ZAPServer) Handle(ctx context.Context, msgType uint8, payload []byte) error {
	switch zapwire.MessageType(msgType) {
	case zapwire.MsgSendRequest:
		return s.HandleSendRequest(ctx, payload)
	case zapwire.MsgSendResponse:
		return s.HandleSendResponse(ctx, payload)
	case zapwire.MsgSendError:
		return s.HandleSendError(ctx, payload)
	case zapwire.MsgSendGossip:
		return s.HandleSendGossip(ctx, payload)
	default:
		return nil
	}
}

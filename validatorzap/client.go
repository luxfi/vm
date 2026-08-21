// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package validatorzap

import (
	"context"
	"fmt"

	zapwire "github.com/luxfi/api/zap"
	"github.com/luxfi/ids"
	"github.com/luxfi/validators"
)

// Client is a plugin-side validators.State backed by the node's handle.
//
// It implements the FULL interface, not only the method M-Chain happens to call.
// A partial implementation would compile and the missing methods would return
// zero — and a zero validator set is not a smaller answer to the same question,
// it is a different quorum.
type Client struct {
	conn *zapwire.Conn
}

var _ validators.State = (*Client)(nil)

// Dial connects to a node-hosted validator server.
//
// An empty addr means the node wired no validator state for the chain, so this
// refuses rather than returning a client that would answer every query with an
// empty set.
func Dial(ctx context.Context, addr string) (*Client, error) {
	if addr == "" {
		return nil, ErrNoValidatorState
	}
	cfg := zapwire.DefaultConfig()
	// A validator-set read sits on the ceremony path, which is slow by nature —
	// a DKG round waits on peers. A read deadline expiring mid-call would surface
	// as a transport error whose timing differs per node: a ceremony failing on
	// some validators and not others for no reason in the protocol.
	cfg.ReadTimeout = 0
	conn, err := zapwire.Dial(ctx, addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("validatorzap: dial %q: %w", addr, err)
	}
	return &Client{conn: conn}, nil
}

func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// ask sends one query and returns a scan over the reply. Every method below is
// then its arguments and its result shape, with no transport in between.
func (c *Client) ask(ctx context.Context, m method, args func(*zapwire.Buffer)) (*scan, error) {
	if c == nil || c.conn == nil {
		return nil, ErrNoValidatorState
	}
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	buf.WriteUint8(uint8(m))
	if args != nil {
		args(buf)
	}

	respType, respData, err := c.conn.Call(ctx, zapwire.MsgValidatorState, buf.Bytes())
	if err != nil {
		return nil, err
	}
	if respType&^(zapwire.MsgResponseFlag|zapwire.MsgErrorFlag) != zapwire.MsgValidatorState {
		return nil, fmt.Errorf("validatorzap: unexpected response type %d", respType)
	}
	return newScan(respData), nil
}

func heightAndNet(height uint64, netID ids.ID) func(*zapwire.Buffer) {
	return func(buf *zapwire.Buffer) {
		buf.WriteUint64(height)
		buf.WriteBytes(netID[:])
	}
}

func (c *Client) set(ctx context.Context, m method, height uint64, netID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	s, err := c.ask(ctx, m, heightAndNet(height, netID))
	if err != nil {
		return nil, err
	}
	out := s.validatorSet()
	return out, s.err
}

func (c *Client) GetValidatorSet(ctx context.Context, height uint64, netID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	return c.set(ctx, mValidatorSet, height, netID)
}

func (c *Client) GetCurrentValidators(ctx context.Context, height uint64, netID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	return c.set(ctx, mCurrentValidators, height, netID)
}

func (c *Client) height(ctx context.Context, m method) (uint64, error) {
	s, err := c.ask(ctx, m, nil)
	if err != nil {
		return 0, err
	}
	v := s.u64()
	return v, s.err
}

func (c *Client) GetCurrentHeight(ctx context.Context) (uint64, error) {
	return c.height(ctx, mCurrentHeight)
}

func (c *Client) GetMinimumHeight(ctx context.Context) (uint64, error) {
	return c.height(ctx, mMinimumHeight)
}

func (c *Client) lookup(m method, in ids.ID) (ids.ID, error) {
	s, err := c.ask(context.Background(), m, func(buf *zapwire.Buffer) { buf.WriteBytes(in[:]) })
	if err != nil {
		return ids.Empty, err
	}
	v := s.id()
	return v, s.err
}

func (c *Client) GetChainID(netID ids.ID) (ids.ID, error)   { return c.lookup(mChainID, netID) }
func (c *Client) GetNetworkID(chainID ids.ID) (ids.ID, error) { return c.lookup(mNetworkID, chainID) }

func (c *Client) GetWarpValidatorSet(ctx context.Context, height uint64, netID ids.ID) (*validators.WarpSet, error) {
	s, err := c.ask(ctx, mWarpSet, heightAndNet(height, netID))
	if err != nil {
		return nil, err
	}
	ws := s.warpSet()
	return ws, s.err
}

func (c *Client) GetWarpValidatorSets(ctx context.Context, heights []uint64, netIDs []ids.ID) (map[ids.ID]map[uint64]*validators.WarpSet, error) {
	s, err := c.ask(ctx, mWarpSets, func(buf *zapwire.Buffer) {
		buf.WriteUint32(uint32(len(heights)))
		for _, h := range heights {
			buf.WriteUint64(h)
		}
		buf.WriteUint32(uint32(len(netIDs)))
		for _, id := range netIDs {
			n := id
			buf.WriteBytes(n[:])
		}
	})
	if err != nil {
		return nil, err
	}
	out := s.warpSets()
	return out, s.err
}

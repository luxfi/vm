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
// It implements the FULL interface rather than only the method M-Chain happens
// to call. A partial implementation would compile — the missing methods would
// panic or return zero — and a zero validator set is not a smaller answer, it is
// a different quorum. Every method therefore either answers or errors.
type Client struct {
	conn *zapwire.Conn
}

var _ validators.State = (*Client)(nil)

// Dial connects to a node-hosted validator server.
//
// A caller holding an empty addr must NOT call this. An absent address means the
// node wired no validator state for the chain, and the plugin must leave
// Runtime.ValidatorState nil so a committee lookup fails loudly rather than
// succeeding over an empty set.
func Dial(ctx context.Context, addr string) (*Client, error) {
	if addr == "" {
		return nil, ErrNoValidatorState
	}
	cfg := zapwire.DefaultConfig()
	// A validator-set read sits on the ceremony path, which is slow by nature —
	// a DKG round waits on peers. A read deadline expiring mid-call would surface
	// as a transport error whose timing differs per node, i.e. a ceremony that
	// fails on some validators and not others for no reason in the protocol.
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

func (c *Client) call(ctx context.Context, enc func(*zapwire.Buffer)) ([]byte, error) {
	const msgType = zapwire.MsgValidatorState
	if c == nil || c.conn == nil {
		return nil, ErrNoValidatorState
	}
	buf := zapwire.GetBuffer()
	defer zapwire.PutBuffer(buf)
	enc(buf)

	respType, respData, err := c.conn.Call(ctx, msgType, buf.Bytes())
	if err != nil {
		return nil, err
	}
	if respType&^(zapwire.MsgResponseFlag|zapwire.MsgErrorFlag) != msgType {
		return nil, fmt.Errorf("validatorzap: unexpected response type %d for request %d", respType, msgType)
	}
	return respData, nil
}

func (c *Client) getSet(ctx context.Context, m method, height uint64, netID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	data, err := c.call(ctx, func(buf *zapwire.Buffer) {
		buf.WriteUint8(uint8(m))
		buf.WriteUint64(height)
		buf.WriteBytes(netID[:])
	})
	if err != nil {
		return nil, err
	}
	return readValidators(zapwire.NewReader(data))
}

func (c *Client) GetValidatorSet(ctx context.Context, height uint64, netID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	return c.getSet(ctx, mValidatorSet, height, netID)
}

func (c *Client) GetCurrentValidators(ctx context.Context, height uint64, netID ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
	return c.getSet(ctx, mCurrentValidators, height, netID)
}

func (c *Client) getHeight(ctx context.Context, m method) (uint64, error) {
	data, err := c.call(ctx, func(buf *zapwire.Buffer) { buf.WriteUint8(uint8(m)) })
	if err != nil {
		return 0, err
	}
	return zapwire.NewReader(data).ReadUint64()
}

func (c *Client) GetCurrentHeight(ctx context.Context) (uint64, error) {
	return c.getHeight(ctx, mCurrentHeight)
}

func (c *Client) GetMinimumHeight(ctx context.Context) (uint64, error) {
	return c.getHeight(ctx, mMinimumHeight)
}

func (c *Client) getID(m method, in ids.ID) (ids.ID, error) {
	data, err := c.call(context.Background(), func(buf *zapwire.Buffer) {
		buf.WriteUint8(uint8(m))
		buf.WriteBytes(in[:])
	})
	if err != nil {
		return ids.Empty, err
	}
	raw, err := zapwire.NewReader(data).ReadBytes()
	if err != nil {
		return ids.Empty, err
	}
	return ids.ToID(raw)
}

func (c *Client) GetChainID(netID ids.ID) (ids.ID, error) {
	return c.getID(mChainID, netID)
}

func (c *Client) GetNetworkID(chainID ids.ID) (ids.ID, error) {
	return c.getID(mNetworkID, chainID)
}

func (c *Client) GetWarpValidatorSet(ctx context.Context, height uint64, netID ids.ID) (*validators.WarpSet, error) {
	data, err := c.call(ctx, func(buf *zapwire.Buffer) {
		buf.WriteUint8(uint8(mWarpSet))
		buf.WriteUint64(height)
		buf.WriteBytes(netID[:])
	})
	if err != nil {
		return nil, err
	}
	return readWarpSet(zapwire.NewReader(data))
}

func (c *Client) GetWarpValidatorSets(ctx context.Context, heights []uint64, netIDs []ids.ID) (map[ids.ID]map[uint64]*validators.WarpSet, error) {
	data, err := c.call(ctx, func(buf *zapwire.Buffer) {
		buf.WriteUint8(uint8(mWarpSets))
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
	r := zapwire.NewReader(data)
	n, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	out := make(map[ids.ID]map[uint64]*validators.WarpSet, n)
	for i := uint32(0); i < n; i++ {
		raw, err := r.ReadBytes()
		if err != nil {
			return nil, err
		}
		netID, err := ids.ToID(raw)
		if err != nil {
			return nil, err
		}
		m, err := r.ReadUint32()
		if err != nil {
			return nil, err
		}
		byHeight := make(map[uint64]*validators.WarpSet, m)
		for j := uint32(0); j < m; j++ {
			height, err := r.ReadUint64()
			if err != nil {
				return nil, err
			}
			ws, err := readWarpSet(r)
			if err != nil {
				return nil, err
			}
			byHeight[height] = ws
		}
		out[netID] = byHeight
	}
	return out, nil
}

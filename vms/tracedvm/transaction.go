// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package tracedvm

import (
	"context"

	"go.opentelemetry.io/otel/attribute"

	"github.com/luxfi/consensus/engine/dag"
	"github.com/luxfi/ids"
	"github.com/luxfi/trace"

	oteltrace "go.opentelemetry.io/otel/trace"
)

var _ dag.Transaction = (*tracedTransaction)(nil)

type tracedTransaction struct {
	dag.Transaction

	tracer trace.Tracer
}

func (t *tracedTransaction) ID() ids.ID {
	return t.Transaction.ID()
}

func (t *tracedTransaction) Parent() ids.ID {
	return t.Transaction.Parent()
}

func (t *tracedTransaction) Height() uint64 {
	return t.Transaction.Height()
}

func (t *tracedTransaction) Bytes() []byte {
	return t.Transaction.Bytes()
}

func (t *tracedTransaction) Verify(ctx context.Context) error {
	ctx, span := t.tracer.Start(ctx, "tracedTransaction.Verify", oteltrace.WithAttributes(
		attribute.Stringer("txID", t.Transaction.ID()),
	))
	defer span.End()

	return t.Transaction.Verify(ctx)
}

func (t *tracedTransaction) Accept(ctx context.Context) error {
	ctx, span := t.tracer.Start(ctx, "tracedTransaction.Accept", oteltrace.WithAttributes(
		attribute.Stringer("txID", t.Transaction.ID()),
	))
	defer span.End()

	return t.Transaction.Accept(ctx)
}

func (t *tracedTransaction) Reject(ctx context.Context) error {
	ctx, span := t.tracer.Start(ctx, "tracedTransaction.Reject", oteltrace.WithAttributes(
		attribute.Stringer("txID", t.Transaction.ID()),
	))
	defer span.End()

	return t.Transaction.Reject(ctx)
}

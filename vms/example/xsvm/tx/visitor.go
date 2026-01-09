// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package tx

type Visitor interface {
	Transfer(*Transfer) error
	Export(*Export) error
	Import(*Import) error
}

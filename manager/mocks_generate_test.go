// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package manager

// The mock is generated from the interface, so adding a method to Manager and
// forgetting the mock is a regeneration away rather than a puzzle: without this
// the mock silently kept four of eight methods and every test that used it
// stopped compiling against its own package.
//go:generate go run go.uber.org/mock/mockgen -package=${GOPACKAGE}mock -destination=${GOPACKAGE}mock/manager.go -mock_names=Manager=Manager . Manager
//go:generate go run go.uber.org/mock/mockgen -package=${GOPACKAGE}mock -destination=${GOPACKAGE}mock/factory.go -mock_names=Factory=Factory . Factory

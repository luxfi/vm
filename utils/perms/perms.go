// Package perms provides compatibility with old import path.
// Deprecated: Use github.com/luxfi/filesystem/perms instead.
package perms

import "github.com/luxfi/filesystem/perms"

// Re-export constants from github.com/luxfi/filesystem/perms
const (
	ReadOnly         = perms.ReadOnly
	ReadWrite        = perms.ReadWrite
	ReadWriteExecute = perms.ReadWriteExecute
)

// Re-export functions
var (
	ChmodR    = perms.ChmodR
	Create    = perms.Create
	WriteFile = perms.WriteFile
)

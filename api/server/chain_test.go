// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package server

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zap-proto/zip"

	"github.com/luxfi/constants"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/metric"
)

// gone is the segment chains used to answer on, written once so this file never
// spells the address it is asserting is unreachable.
const gone = "bc"

// newServer builds the shipped server and hands back both it and the handler
// its listener would serve: the router underneath CORS and the host filter, not
// the router alone. Routes are asserted through that whole chain.
func newServer(t *testing.T) (Server, http.Handler) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	s, err := New(
		log.NoLog{},
		ln,
		[]string{"*"},
		time.Second,
		ids.EmptyNodeID,
		false,
		nil,
		metric.NewRegistry(),
		HTTPConfig{},
		[]string{"*"},
	)
	require.NoError(t, err)
	return s, s.(*server).handler
}

// TestChainAnswersUnderOneSegment measures where a chain is reachable, on a
// real mounted app rather than on a claim about the route table: a typed op
// answers under [constants.ChainAliasPrefix], and the segment that prefix
// replaced answers nothing.
func TestChainAnswersUnderOneSegment(t *testing.T) {
	require := require.New(t)
	s, serve := newServer(t)

	app := zip.New(zip.Config{AppName: "platform"})

	// Height of the last accepted block.
	zip.Get(app, "/height", func(context.Context, *struct{}) (*height, error) {
		return &height{Height: 7}, nil
	})

	handler, err := Mount(app)
	require.NoError(err)
	t.Cleanup(func() { _ = app.Shutdown() })

	// Mounted the one way the chain manager mounts a chain: the app at the
	// chain's base, under Ops.
	require.NoError(s.AddRoute(handler, constants.ChainAliasPrefix+"/P", Ops))

	body, code := ask(t, serve, Chain("", "P")+Ops+"/height")
	require.Equal(http.StatusOK, code, body)
	require.JSONEq(`{"height":7}`, body)

	for _, dead := range []string{
		fmt.Sprintf("%s/%s/P%s/height", baseURL, gone, Ops),
		fmt.Sprintf("%s/%s/P%s", baseURL, gone, Ops),
		fmt.Sprintf("%s/%s/P/height", baseURL, gone),
		fmt.Sprintf("%s/%s/P", baseURL, gone),
	} {
		body, code := ask(t, serve, dead)
		require.Equal(http.StatusNotFound, code, "%s still answers: %s", dead, body)
	}
}

// TestChainAddressBuiltOnlyHere fails if any Go source in this module writes a
// chain address out by hand instead of calling [Chain].
//
// This is what stops the segment drifting back. When it last changed, the
// router moved and three shipped clients did not — the P-Chain client the
// wallet is built on, the wallet's own X-Chain requester, and the heartbeat
// example had each spelled the segment themselves. Nothing failed to compile.
// They simply went on addressing a name that was no longer served.
//
// It reads string literals, so prose describing a route stays free to name it;
// only building one is the error. The patterns are assembled rather than
// written, so this file is not its own first offender.
func TestChainAddressBuiltOnlyHere(t *testing.T) {
	forbidden := []struct{ frag, why string }{
		{baseURL + "/" + gone, "addresses a chain under a segment that is not served"},
		{baseURL + "/" + constants.ChainAliasPrefix, "spells the chain segment; call server.Chain(uri, alias)"},
		{baseURL + "/%s", "interpolates the chain segment; call server.Chain(uri, alias)"},
	}

	var bad []string
	fset := token.NewFileSet()
	root := moduleRoot(t)

	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "testdata", "node_modules":
				return fs.SkipDir
			}
			// A nested module is a different program with a different
			// dependency set, and some of them exist precisely so they can
			// carry what the node must not — conformance/dex links an EVM ABI
			// and a signer. Such a module cannot import [Chain], so requiring
			// it to call [Chain] would be asking it to depend on the node to
			// avoid spelling a string. The rule this test enforces is about
			// THIS module.
			if p != root {
				if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
					return fs.SkipDir
				}
			}
			return nil
		}
		if filepath.Ext(p) != ".go" {
			return nil
		}
		// A file that will not parse is the build's problem, not this test's.
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for _, f := range forbidden {
				if strings.Contains(text, f.frag) {
					at := fset.Position(lit.Pos())
					rel, _ := filepath.Rel(root, at.Filename)
					bad = append(bad, fmt.Sprintf("%s:%d: %s\n\t%s",
						filepath.ToSlash(rel), at.Line, f.why, lit.Value))
				}
			}
			return true
		})
		return nil
	}))

	require.Empty(t, bad, "a chain address is built in exactly one place, [Chain]:\n%s", strings.Join(bad, "\n"))
}

// TestChainDerivesFromTheConstant pins Chain to the constant rather than to a
// copy of its current value, so renaming the segment renames the route.
func TestChainDerivesFromTheConstant(t *testing.T) {
	require.Equal(t, baseURL+"/"+constants.ChainAliasPrefix+"/P", Chain("", "P"))
	require.Equal(t, "http://n:9630"+baseURL+"/"+constants.ChainAliasPrefix+"/C", Chain("http://n:9630", "C"))
	require.Contains(t, Chain("", "X"), constants.ChainAliasPrefix)
	require.NotContains(t, Chain("", "X"), "/"+gone+"/")
}

// moduleRoot walks up from the package directory to the directory holding
// go.mod, so the scan covers the module rather than this package.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "no go.mod above the package directory")
		dir = parent
	}
}

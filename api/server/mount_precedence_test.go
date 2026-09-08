// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// mount_precedence_test.go — which endpoint owns a path, once endpoints own the
// paths beneath them.
//
// Serving below a mount answers "can this handler be reached"; it does not say
// WHICH handler a path belongs to when several could claim it. Two rules decide
// that, and both are load-bearing: an exact route always beats a mount, and
// among mounts the longest one wins. Neither is stated anywhere but in the
// direction a loop happens to count.
package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

func namedHandler(name string, seen *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		*seen = req.URL.Path
		_, _ = w.Write([]byte(name))
	})
}

// TestDeepestMountOwnsThePath is the rule the scan direction encodes.
//
// A chain mounts several endpoints under one base, and one endpoint's path is a
// prefix of another's: /rpc and /rpc/admin. A request to /rpc/admin/purge lives
// under both. It belongs to the deeper one — /rpc/admin — because that is the
// endpoint that named it. Scanning outward from the shallowest mount instead
// would hand every admin path to /rpc, which is the endpoint that did not ask
// for it.
func TestDeepestMountOwnsThePath(t *testing.T) {
	r := newRouter()
	base := Chain("", ids.GenerateTestID().String())
	var seen string
	require.NoError(t, r.AddRouter(base, "/rpc", namedHandler("rpc", &seen)))
	require.NoError(t, r.AddRouter(base, "/rpc/admin", namedHandler("admin", &seen)))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, base+"/rpc/admin/purge", nil))

	require.Equal(t, "admin", rec.Body.String(),
		"a path under two mounts belongs to the deeper one — the endpoint that named it")
	require.Equal(t, "/purge", seen,
		"the handler must be given the path relative to ITS mount, not to the shallower one")
}

// TestExactRouteBeatsAMount keeps a sibling from being swallowed. /health and
// /health/readiness are two endpoints, not one endpoint and a path beneath it,
// so /health/readiness must reach its own handler on its own full path — the
// mount fallback is a fallback, and an exact match is not a miss.
func TestExactRouteBeatsAMount(t *testing.T) {
	r := newRouter()
	base := baseURL + "/health"
	var seen string
	require.NoError(t, r.AddRouter(base, "", namedHandler("root", &seen)))
	require.NoError(t, r.AddRouter(base, "/readiness", namedHandler("readiness", &seen)))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, base+"/readiness", nil))

	require.Equal(t, "readiness", rec.Body.String(), "an exact route must never fall through to a mount")
	require.Equal(t, base+"/readiness", seen,
		"an exactly-matched endpoint keeps the whole path; only the fallback strips")
}

// TestAnUnmountedPathIs404 is the other half of the fallback: it may only reach
// handlers that were actually mounted. A path under no endpoint is still a
// miss, or the node answers for chains it does not run.
func TestAnUnmountedPathIs404(t *testing.T) {
	r := newRouter()
	base := Chain("", ids.GenerateTestID().String())
	var seen string
	require.NoError(t, r.AddRouter(base, "/rpc", namedHandler("rpc", &seen)))

	for _, path := range []string{
		Chain("", ids.GenerateTestID().String()) + "/rpc/getStatus", // a chain we do not run
		baseURL + "/nothing/at/all",
		"/not/even/ours",
	} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, http.StatusNotFound, rec.Code, "%s must not reach any handler", path)
	}
}

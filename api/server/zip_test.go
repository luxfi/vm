// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zap-proto/zip"
)

type said struct {
	Word string `json:"word"`
}

// TestMount asserts both halves of a mount: a typed op answers an ordinary
// net/http request, and the OpenAPI document answers too. The document is the
// half that says Mount SERVES the app rather than reaching past zip for its
// request handler — the document route is installed by serving.
func TestMount(t *testing.T) {
	require := require.New(t)

	app := zip.New(zip.Config{AppName: "mounted"})
	zip.Get(app, "/say", func(context.Context, *struct{}) (*said, error) {
		return &said{Word: "hello"}, nil
	})

	handler, err := Mount(app)
	require.NoError(err)
	t.Cleanup(func() { _ = app.Shutdown() })

	body, code := ask(t, handler, "/say")
	require.Equal(http.StatusOK, code)
	require.JSONEq(`{"word":"hello"}`, body)

	body, code = ask(t, handler, zip.SpecPath)
	require.Equal(http.StatusOK, code)
	require.Contains(body, `"/say"`)
}

func ask(t *testing.T, handler http.Handler, path string) (string, int) {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	body, err := io.ReadAll(rec.Result().Body)
	require.NoError(t, err)
	return string(body), rec.Code
}

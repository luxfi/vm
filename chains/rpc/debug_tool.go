// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Copyright (C) 2025, Lux Industries Inc All rights reserved.
// See the file LICENSE for licensing terms.

package rpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// DebugTool provides utilities for debugging RPC handler issues.
// Developer-friendly diagnostics with clear, actionable output.
type DebugTool struct {
	baseURL string
	client  *http.Client
	log     log.Logger
}

// NewDebugTool creates a debug tool for RPC endpoint testing.
func NewDebugTool(baseURL string, logger log.Logger) *DebugTool {
	if !strings.HasPrefix(baseURL, "http") {
		baseURL = "http://" + baseURL
	}

	return &DebugTool{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		log: logger,
	}
}

// DiagnoseEndpoint performs comprehensive diagnostics on an RPC endpoint.
// Returns detailed information about what's working and what's not.
func (d *DebugTool) DiagnoseEndpoint(chainID ids.ID, alias string) *DiagnosticReport {
	report := &DiagnosticReport{
		ChainID:   chainID,
		Alias:     alias,
		Timestamp: time.Now(),
		Tests:     make([]TestResult, 0),
	}

	// Test different URL patterns
	urlPatterns := d.getURLPatterns(chainID, alias)

	for _, pattern := range urlPatterns {
		result := d.testEndpoint(pattern)
		report.Tests = append(report.Tests, result)
	}

	// Test common RPC methods
	if bestURL := report.GetBestURL(); bestURL != "" {
		report.RPCTests = d.testRPCMethods(bestURL)
	}

	return report
}

// getURLPatterns returns all possible URL patterns to test.
func (d *DebugTool) getURLPatterns(chainID ids.ID, alias string) []string {
	patterns := []string{
		fmt.Sprintf("%s/ext/bc/%s/rpc", d.baseURL, chainID.String()),
		fmt.Sprintf("%s/ext/bc/%s/ws", d.baseURL, chainID.String()),
		fmt.Sprintf("%s/ext/bc/%s", d.baseURL, chainID.String()),
	}

	if alias != "" && alias != chainID.String() {
		patterns = append(patterns,
			fmt.Sprintf("%s/ext/bc/%s/rpc", d.baseURL, alias),
			fmt.Sprintf("%s/ext/bc/%s/ws", d.baseURL, alias),
			fmt.Sprintf("%s/ext/bc/%s", d.baseURL, alias),
		)
	}

	// Also test without /ext prefix (some setups might differ)
	patterns = append(patterns,
		fmt.Sprintf("%s/bc/%s/rpc", d.baseURL, chainID.String()),
	)

	return patterns
}

// testEndpoint tests a single endpoint URL.
func (d *DebugTool) testEndpoint(url string) TestResult {
	result := TestResult{
		URL:       url,
		Timestamp: time.Now(),
	}

	// First try a simple GET
	resp, err := d.client.Get(url)
	if err != nil {
		result.Error = fmt.Sprintf("GET failed: %v", err)
		result.Success = false
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Read body for debugging
	bodyBytes, _ := io.ReadAll(resp.Body)
	result.Response = string(bodyBytes)

	// Now try a POST with JSON-RPC
	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "web3_clientVersion",
		"params":  []interface{}{},
		"id":      1,
	}

	jsonBytes, _ := json.Marshal(rpcReq)
	postResp, err := d.client.Post(url, "application/json", bytes.NewReader(jsonBytes))
	if err != nil {
		result.Error = fmt.Sprintf("POST failed: %v", err)
		result.Success = false
		return result
	}
	defer postResp.Body.Close()

	result.StatusCode = postResp.StatusCode

	// Check if we got a valid JSON-RPC response
	var rpcResp map[string]interface{}
	if err := json.NewDecoder(postResp.Body).Decode(&rpcResp); err == nil {
		if _, hasResult := rpcResp["result"]; hasResult {
			result.Success = true
			result.Response = fmt.Sprintf("Valid JSON-RPC response: %v", rpcResp["result"])
		} else if errObj, hasError := rpcResp["error"]; hasError {
			result.Success = false
			result.Response = fmt.Sprintf("JSON-RPC error: %v", errObj)
		}
	}

	return result
}

// testRPCMethods tests common RPC methods against an endpoint.
func (d *DebugTool) testRPCMethods(url string) []RPCTest {
	methods := []string{
		"web3_clientVersion",
		"eth_blockNumber",
		"eth_chainId",
		"net_version",
		"eth_syncing",
	}

	tests := make([]RPCTest, 0, len(methods))

	for _, method := range methods {
		test := RPCTest{
			Method: method,
			URL:    url,
		}

		req := map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  method,
			"params":  []interface{}{},
			"id":      1,
		}

		jsonBytes, _ := json.Marshal(req)
		resp, err := d.client.Post(url, "application/json", bytes.NewReader(jsonBytes))
		if err != nil {
			test.Error = err.Error()
			test.Success = false
		} else {
			defer resp.Body.Close()

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
				if res, ok := result["result"]; ok {
					test.Success = true
					test.Result = fmt.Sprintf("%v", res)
				} else if errObj, ok := result["error"]; ok {
					test.Error = fmt.Sprintf("%v", errObj)
				}
			}
		}

		tests = append(tests, test)
	}

	return tests
}

// DiagnosticReport contains comprehensive endpoint diagnostic information.
type DiagnosticReport struct {
	ChainID   ids.ID
	Alias     string
	Timestamp time.Time
	Tests     []TestResult
	RPCTests  []RPCTest
}

// TestResult represents a single endpoint test result.
type TestResult struct {
	URL        string
	Success    bool
	StatusCode int
	Response   string
	Error      string
	Timestamp  time.Time
}

// RPCTest represents a test of a specific RPC method.
type RPCTest struct {
	Method   string
	URL      string
	Success  bool
	Result   string
	Error    string
}

// GetBestURL returns the first working URL from the tests.
func (r *DiagnosticReport) GetBestURL() string {
	for _, test := range r.Tests {
		if test.Success {
			return test.URL
		}
	}
	return ""
}

// String returns a human-readable report.
func (r *DiagnosticReport) String() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("=== RPC Endpoint Diagnostic Report ===\n"))
	b.WriteString(fmt.Sprintf("Chain ID: %s\n", r.ChainID))
	if r.Alias != "" {
		b.WriteString(fmt.Sprintf("Alias: %s\n", r.Alias))
	}
	b.WriteString(fmt.Sprintf("Timestamp: %s\n\n", r.Timestamp.Format(time.RFC3339)))

	b.WriteString("=== Endpoint Tests ===\n")
	for _, test := range r.Tests {
		status := "❌ FAILED"
		if test.Success {
			status = "✅ SUCCESS"
		}
		b.WriteString(fmt.Sprintf("\n%s %s\n", status, test.URL))
		b.WriteString(fmt.Sprintf("  Status Code: %d\n", test.StatusCode))
		if test.Error != "" {
			b.WriteString(fmt.Sprintf("  Error: %s\n", test.Error))
		}
		if test.Response != "" && len(test.Response) < 200 {
			b.WriteString(fmt.Sprintf("  Response: %s\n", test.Response))
		}
	}

	if len(r.RPCTests) > 0 {
		b.WriteString("\n=== RPC Method Tests ===\n")
		for _, test := range r.RPCTests {
			status := "❌"
			if test.Success {
				status = "✅"
			}
			b.WriteString(fmt.Sprintf("%s %s: ", status, test.Method))
			if test.Success {
				b.WriteString(test.Result)
			} else {
				b.WriteString(test.Error)
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n=== Recommendations ===\n")
	if bestURL := r.GetBestURL(); bestURL != "" {
		b.WriteString(fmt.Sprintf("✅ Use this endpoint: %s\n", bestURL))
	} else {
		b.WriteString("❌ No working endpoints found. Check:\n")
		b.WriteString("  1. Is the node running?\n")
		b.WriteString("  2. Is the chain bootstrapped?\n")
		b.WriteString("  3. Are handlers properly registered?\n")
		b.WriteString("  4. Check node logs for handler registration errors\n")
		b.WriteString("  5. Try restarting the node\n")
	}

	return b.String()
}

// QuickDiagnose performs a quick endpoint check and prints results.
// Convenience function for CLI tools.
func QuickDiagnose(nodeURL string, chainID ids.ID, alias string) {
	logger := log.NewNoOpLogger()
	tool := NewDebugTool(nodeURL, logger)
	report := tool.DiagnoseEndpoint(chainID, alias)
	fmt.Println(report.String())
}
// Copyright (C) 2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"context"
	"strings"

	"github.com/luxfi/database"
)

// GConfig configures GraphVM query execution.
type GConfig struct {
	MaxQueryDepth  int
	MaxResultSize  int
	QueryTimeoutMs int
}

// GraphQLRequest represents a GraphQL request payload.
type GraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// GraphQLError represents a GraphQL error.
type GraphQLError struct {
	Message string `json:"message"`
}

// GraphQLResponse represents a GraphQL response payload.
type GraphQLResponse struct {
	Data   map[string]interface{} `json:"data,omitempty"`
	Errors []GraphQLError         `json:"errors,omitempty"`
}

// ResolverFunc is a resolver callback for custom queries.
type ResolverFunc func(ctx context.Context, db database.Database, args map[string]interface{}) (interface{}, error)

// QueryExecutor executes GraphQL queries against the GraphVM.
type QueryExecutor struct {
	db        database.Database
	config    *GConfig
	resolvers map[string]ResolverFunc
}

// NewQueryExecutor creates a new QueryExecutor.
func NewQueryExecutor(db database.Database, config *GConfig) *QueryExecutor {
	return &QueryExecutor{
		db:        db,
		config:    config,
		resolvers: make(map[string]ResolverFunc),
	}
}

// Execute runs a GraphQL request and returns the response.
// This is a minimal in-process implementation to satisfy precompile usage.
func (q *QueryExecutor) Execute(ctx context.Context, req *GraphQLRequest) *GraphQLResponse {
	resp := &GraphQLResponse{
		Data: make(map[string]interface{}),
	}
	if req == nil {
		resp.Errors = append(resp.Errors, GraphQLError{Message: "nil request"})
		return resp
	}

	query := req.Query
	if strings.Contains(query, "chainInfo") {
		resp.Data["chainInfo"] = map[string]interface{}{
			"vmName":   "graphvm",
			"version":  "0.1.0",
			"readOnly": false,
		}
	}

	for name, resolver := range q.resolvers {
		if strings.Contains(query, name) {
			value, err := resolver(ctx, q.db, req.Variables)
			if err != nil {
				resp.Errors = append(resp.Errors, GraphQLError{Message: err.Error()})
				continue
			}
			resp.Data[name] = value
		}
	}

	return resp
}

// RegisterResolver registers a custom resolver by name.
func (q *QueryExecutor) RegisterResolver(name string, resolver ResolverFunc) {
	if resolver == nil {
		return
	}
	q.resolvers[name] = resolver
}

// GetDB returns the backing database.
func (q *QueryExecutor) GetDB() database.Database {
	return q.db
}

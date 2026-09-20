// Package security provides security handlers for the application, including a passthrough handler that allows all requests.
package security

import (
	"context"

	"ogen-sec/internal/ogen/api"
)

type passthroughSecurityHandler struct{}

// NewPassthroughSecurityHandler creates a new security handler that allows all requests.
func NewPassthroughSecurityHandler() *passthroughSecurityHandler {
	return &passthroughSecurityHandler{}
}

// HandleBearerAuth implements the api.SecurityHandler interface and allows all bearer authentication requests.
func (p *passthroughSecurityHandler) HandleBearerAuth(ctx context.Context, operationName api.OperationName, t api.BearerAuth) (context.Context, error) {
	return ctx, nil
}

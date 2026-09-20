// Package http adapts the generated OpenAPI server to the application runtime.
package http

import (
	"context"
	"errors"
	"fmt"
	stdhttp "net/http"

	ht "github.com/ogen-go/ogen/http"
	"github.com/ogen-go/ogen/ogenerrors"

	"ogen-sec/internal/ogen/api"
)

const notImplementedMessage = "Not emplemented"

// Embedding the generated fallback lets future handler methods override
// the default 501 behavior without additional wiring changes.
type handler struct {
	api.UnimplementedHandler
}

// NewHandler builds the HTTP handler backed by the generated ogen server.
func NewHandler(secHandler api.SecurityHandler) (stdhttp.Handler, error) {
	server, err := api.NewServer(
		&handler{},
		secHandler,
		api.WithErrorHandler(ogenErrorHandler),
	)
	if err != nil {
		return nil, fmt.Errorf("build ogen server: %w", err)
	}

	return server, nil
}

// func (*handler) NewError(ctx context.Context, err error) *api.DefaultErrorResponseStatusCode {
// 	status := stdhttp.StatusInternalServerError
// 	message := stdhttp.StatusText(status)

// 	var securityErr *ogenerrors.SecurityError
// 	switch {
// 	case errors.Is(err, ht.ErrNotImplemented):
// 		status = stdhttp.StatusNotImplemented
// 		message = notImplementedMessage
// 	case errors.As(err, &securityErr), errors.Is(err, ogenerrors.ErrSecurityRequirementIsNotSatisfied):
// 		status = stdhttp.StatusUnauthorized
// 		message = stdhttp.StatusText(status)
// 	default:
// 		if err != nil {
// 			message = err.Error()
// 		}
// 	}

// 	return &api.DefaultErrorResponseStatusCode{
// 		StatusCode: status,
// 		Response: api.ErrorResponse{
// 			Error: api.NewOptString(message),
// 		},
// 	}
// }

func ogenErrorHandler(ctx context.Context, w stdhttp.ResponseWriter, r *stdhttp.Request, err error) {
	if !errors.Is(err, ht.ErrNotImplemented) {
		ogenerrors.DefaultErrorHandler(ctx, w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(stdhttp.StatusNotImplemented)
	if _, writeErr := w.Write([]byte("{\"error\":\"" + notImplementedMessage + "\"}\n")); writeErr != nil {
		return
	}
}

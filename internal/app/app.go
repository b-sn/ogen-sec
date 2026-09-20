// Package app wires application dependencies and lifecycle.
package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"ogen-sec/internal/config"
	"ogen-sec/internal/security"
	transporthttp "ogen-sec/internal/transport/http"
)

// App owns the broker runtime dependencies and HTTP server.
type App struct {
	cfg        config.Config
	httpServer *http.Server
}

// New builds an application instance from the provided configuration.
func New(ctx context.Context) (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	// API key and Basic auth requests are rejected until their dependencies are configured.
	handler, err := transporthttp.NewHandler(security.NewPassthroughSecurityHandler(nil, nil, nil))
	if err != nil {
		return nil, fmt.Errorf("build http handler: %w", err)
	}

	httpServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%s", cfg.HTTPAddress, cfg.HTTPPort),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return &App{
		cfg:        cfg,
		httpServer: httpServer,
	}, nil
}

// Run starts the HTTP server and blocks until it stops.
func (a *App) Run() error {
	listener, err := net.Listen("tcp", a.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("listen http server on %q: %w", a.httpServer.Addr, err)
	}

	addr := a.cfg.HTTPAddress
	if addr == "0.0.0.0" {
		addrCmd := exec.Command("sh", "-c", "ip -4 route get 1.1.1.1 | awk '{print $7}'")
		out, err := addrCmd.Output()
		if err == nil {
			addr = strings.TrimSpace(string(out))
		}
	}
	log.Printf("task-broker listening at http://%s:%s", addr, a.cfg.HTTPPort)

	err = a.httpServer.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}

	return nil
}

// Shutdown gracefully stops the HTTP server and closes the database.
func (a *App) Shutdown(ctx context.Context) error {
	var shutdownErr error

	if a.httpServer != nil {
		if err := a.httpServer.Shutdown(ctx); err != nil {
			shutdownErr = errors.Join(shutdownErr, fmt.Errorf("shutdown http server: %w", err))
		}
	}

	return shutdownErr
}

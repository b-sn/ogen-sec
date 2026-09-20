// Package main starts the task broker service.
package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"
	"time"

	"ogen-sec/internal/app"
)

func main() {
	ctx := context.Background()

	application, err := app.New(ctx)
	if err != nil {
		log.Fatalf("build app: %v", err)
	}

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- application.Run()
	}()

	stopCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-runErrCh:
		if err != nil {
			log.Fatalf("run app: %v", err)
		}
	case <-stopCtx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := application.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("shutdown app: %v", err)
	}
}

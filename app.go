package app

import (
	"context"
	"github.com/MultiAdaptive/transitStation/config"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

type App struct {
	config *config.Config
}

func NewApp(cfg *config.Config) *App {
	InitLogger(cfg.LogLevel)
	return &App{
		config: cfg,
	}
}

func (a *App) Start() error {
	log := GetLogger()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize and start the server
	srv, err := NewServer(ctx, a.config, log)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
		return err
	}

	// Start the server in a goroutine
	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Server error: %v", err)
			os.Exit(1)
		}
	}()

	// Set up channel to listen for interrupt signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		// Block until we receive a signal
		cancel()
		log.Info("Shutting down server...")
	}

	// Attempt to gracefully shutdown the server
	if err := srv.Shutdown(ctx); err != nil {
		log.Errorf("Server forced to shutdown: %v", err)
	}

	log.Info("Server exiting")
	return nil
}

package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"milvago/server/internal/app"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e := run(ctx, log); e != nil {
		log.Error("Milvago failed", "error", e)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger) error {
	c, e := app.LoadConfig()
	if e != nil {
		return e
	}
	startup, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	open := app.OpenRuntimeDatabase
	if c.RunsMigrations() {
		open = app.OpenDatabase
	}
	db, e := open(startup, c)
	if e != nil {
		return e
	}
	defer db.Close()
	if c.ProcessRole() == app.RoleMigrate {
		if e = app.Bootstrap(startup, c, db, log); e == nil {
			log.Info("Milvago migration completed", "edition", app.Edition)
		}
		return e
	}
	a, e := app.New(startup, c, db, log)
	if e != nil {
		return e
	}
	defer a.CloseExportConnections()
	cancel()
	srv := &http.Server{Addr: c.Listen, Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 100 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 * 1024}
	listener, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return e
	}
	workers := []func(context.Context){}
	switch c.ProcessRole() {
	case app.RoleAll:
		workers = append(workers, a.Maintain, a.RunExports)
	case app.RoleMaintenance:
		workers = append(workers, a.Maintain)
	case app.RoleExports:
		workers = append(workers, a.RunExports)
	}
	log.Info("Milvago listening", "address", c.Listen, "edition", app.Edition, "role", c.ProcessRole())
	return serveAndDrain(ctx, srv, listener, 110*time.Second, workers...)
}

// The signal stops new work first. Shutdown is awaited in the main goroutine,
// while request contexts remain alive until their responses finish. Background
// jobs honor cancellation and are joined before the database pool is closed.
func serveAndDrain(ctx context.Context, srv *http.Server, listener net.Listener, grace time.Duration, workers ...func(context.Context)) error {
	background, stop := context.WithCancel(ctx)
	defer stop()
	var tasks sync.WaitGroup
	for _, worker := range workers {
		tasks.Add(1)
		go func(work func(context.Context)) {
			defer tasks.Done()
			work(background)
		}(worker)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(listener) }()
	var serveError error
	select {
	case <-ctx.Done():
	case serveError = <-served:
	}
	stop()
	deadline, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	shutdownError := srv.Shutdown(deadline)
	if shutdownError != nil {
		_ = srv.Close()
	}
	done := make(chan struct{})
	go func() {
		tasks.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-deadline.Done():
		return errors.Join(serveError, shutdownError, errors.New("background shutdown deadline exceeded"))
	}
	if errors.Is(serveError, http.ErrServerClosed) {
		serveError = nil
	}
	return errors.Join(serveError, shutdownError)
}

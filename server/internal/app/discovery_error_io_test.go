package app

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type discoveryDeniedBlockingWriter struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	proceed chan struct{}
	once    sync.Once
}

func (writer *discoveryDeniedBlockingWriter) block() {
	writer.once.Do(func() { close(writer.entered) })
	<-writer.proceed
}
func (writer *discoveryDeniedBlockingWriter) WriteHeader(status int) {
	writer.block()
	writer.ResponseRecorder.WriteHeader(status)
}
func (writer *discoveryDeniedBlockingWriter) Write(value []byte) (int, error) {
	writer.block()
	return writer.ResponseRecorder.Write(value)
}

func TestDiscoveryDeniedAuthorizationEndsTransactionBeforeErrorIO(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	if _, err := f.admin.Exec(ctx, `DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2`, f.org, f.user); err != nil {
		t.Fatal(err)
	}
	writer := &discoveryDeniedBlockingWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), proceed: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(writer.proceed) }) }
	done := make(chan struct{})
	t.Cleanup(func() {
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("denied request worker did not stop")
		}
	})
	request := httptest.NewRequest("GET", "/api/discovery/applications", nil)
	request.AddCookie(f.owner)
	go func() {
		defer close(done)
		f.a.Handler().ServeHTTP(writer, request)
	}()
	select {
	case <-writer.entered:
	case <-done:
		t.Fatal("request ended before its error response")
	case <-time.After(5 * time.Second):
		t.Fatal("authorization error did not reach response I/O")
	}
	if f.a.db.Stat().AcquiredConns() != 0 {
		t.Fatal("authorization error retained a transaction during client I/O", f.a.db.Stat().AcquiredConns())
	}
	probe, err := f.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Rollback(ctx)
	if _, err = probe.Exec(ctx, `SET LOCAL lock_timeout='500ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err = probe.Exec(ctx, `SELECT pg_advisory_xact_lock(`+barrierKeySQL+`)`, f.org); err != nil {
		t.Fatal("slow error response retained the privacy barrier", err)
	}
	if err = probe.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	release()
	<-done
	requireHTTP(t, writer.ResponseRecorder, 403)
}

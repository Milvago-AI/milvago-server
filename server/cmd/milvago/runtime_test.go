package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeAndDrainWaitsForRequestAndBackground(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requestStarted, finishRequest := make(chan struct{}), make(chan struct{})
	backgroundCanceled, finishBackground := make(chan struct{}), make(chan struct{})
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-finishRequest
		_, _ = io.WriteString(w, "committed")
	})}
	done := make(chan error, 1)
	go func() {
		done <- serveAndDrain(ctx, srv, listener, 3*time.Second, func(ctx context.Context) {
			<-ctx.Done()
			close(backgroundCanceled)
			<-finishBackground
		})
	}()
	clientDone := make(chan error, 1)
	go func() {
		response, e := http.Get("http://" + listener.Addr().String())
		if e == nil {
			defer response.Body.Close()
			var body []byte
			body, e = io.ReadAll(response.Body)
			if e == nil && string(body) != "committed" {
				e = io.ErrUnexpectedEOF
			}
		}
		clientDone <- e
	}()
	select {
	case <-requestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("request never reached the handler")
	}
	cancel()
	select {
	case <-backgroundCanceled:
	case <-time.After(2 * time.Second):
		t.Fatal("background did not observe shutdown")
	}
	select {
	case e := <-done:
		t.Fatalf("shutdown returned before request finished: %v", e)
	case <-time.After(25 * time.Millisecond):
	}
	close(finishRequest)
	if e := <-clientDone; e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		t.Fatalf("shutdown returned before background finished: %v", e)
	case <-time.After(25 * time.Millisecond):
	}
	close(finishBackground)
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not complete")
	}
}

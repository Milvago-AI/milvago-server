package app

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestDataReadDeadlinePolicy(t *testing.T) {
	for _, test := range []struct {
		method, path string
		budget       time.Duration
	}{
		{"GET", "/api/overview", 15 * time.Second},
		{"HEAD", "/api/devices", 15 * time.Second},
		{"POST", mcpPath, 15 * time.Second},
		{"POST", "/api/dlp/compile", 15 * time.Second},
		{"POST", "/api/dlp/evaluate", 15 * time.Second},
		{"POST", "/api/discovery/catalog/evaluate", 15 * time.Second},
		{"POST", "/api/ai-governance/systems/validate", 15 * time.Second},
		{"GET", "/api/shadow/export", 90 * time.Second},
		{"GET", "/api/installer/linux", 90 * time.Second},
		{"PUT", "/api/settings", 0},
		{"POST", "/api/discovery/runs", 0},
		{"POST", "/api/discovery/catalog/publish", 0},
		{"GET", "/auth/callback", 0},
		{"GET", "/assets/index.js", 0},
	} {
		t.Run(test.method+test.path, func(t *testing.T) {
			r := httptest.NewRequest(test.method, test.path, nil)
			start := time.Now()
			scoped, cancel := dataReadRequest(r)
			defer cancel()
			deadline, bounded := scoped.Context().Deadline()
			if test.budget == 0 {
				if bounded {
					t.Fatal("unexpected deadline on a mutation, auth or static request")
				}
				return
			}
			if !bounded || deadline.Before(start.Add(test.budget-time.Second)) || deadline.After(time.Now().Add(test.budget)) {
				t.Fatalf("invalid read deadline: %v", deadline)
			}
			cancel()
			if !errors.Is(scoped.Context().Err(), context.Canceled) {
				t.Fatal("read scope not released")
			}
		})
	}
}

func TestDataReadPreservesEarlierCancellationAndErrorBoundaries(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r := httptest.NewRequest("GET", "/api/devices", nil).WithContext(parent)
	scoped, done := dataReadRequest(r)
	defer done()
	want, _ := parent.Deadline()
	actual, _ := scoped.Context().Deadline()
	if !want.Equal(actual) {
		t.Fatal("read enlarged caller deadline")
	}
	for _, err := range []error{context.DeadlineExceeded, &pgconn.PgError{Code: "57014"}} {
		var api apiError
		if !errors.As(dataReadFailure(r, err), &api) || api.status != 504 || api.code != "read_timeout" {
			t.Fatal("read timeout not actionable")
		}
	}
	permission := forbidden()
	if dataReadFailure(r, permission) != permission {
		t.Fatal("permission refusal changed")
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if dataReadFailure(r.WithContext(expired), permission) != permission {
		t.Fatal("expired read masked an explicit access refusal")
	}
	if dataReadFailure(r.WithContext(expired), nil) != nil {
		t.Fatal("successful handler turned into a failure")
	}
	mutation := httptest.NewRequest("PUT", "/api/settings", nil)
	if dataReadFailure(mutation, context.DeadlineExceeded) != context.DeadlineExceeded {
		t.Fatal("mutation outcome presented as a read failure")
	}
}

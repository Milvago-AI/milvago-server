package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	dataReadBudget     = 15 * time.Second
	dataDownloadBudget = 90 * time.Second
	regexReadBudget    = 5 * time.Second
)

// Bound cooperative database and network work for reads. Mutations retain their
// existing lifetime: a read timeout must not imply a write failed.
func dataReadRequest(r *http.Request) (*http.Request, context.CancelFunc) {
	read := (r.Method == http.MethodGet || r.Method == http.MethodHead) && strings.HasPrefix(r.URL.Path, "/api/")
	read = read || readOnlyPost(r)
	if !read && r.URL.Path != mcpPath {
		return r, func() {}
	}
	budget := dataReadBudget
	if r.URL.Path == "/api/shadow/export" || strings.HasPrefix(r.URL.Path, "/api/installer/") {
		budget = dataDownloadBudget
	}
	if strings.HasPrefix(r.URL.Path, "/api/shadow/") && len(r.URL.Query()["regex"]) > 0 && budget > regexReadBudget {
		budget = regexReadBudget
	}
	ctx, cancel := context.WithTimeout(r.Context(), budget)
	return r.WithContext(ctx), cancel
}

func dataReadFailure(r *http.Request, err error) error {
	var explicit apiError
	if err == nil || errors.As(err, &explicit) {
		return err
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.URL.Path != mcpPath && !readOnlyPost(r) {
		return err
	}
	var databaseError *pgconn.PgError
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(r.Context().Err(), context.DeadlineExceeded) || (errors.As(err, &databaseError) && databaseError.Code == "57014") {
		return apiError{504, "read_timeout", "The data load took too long. Retry or narrow the selected scope."}
	}
	return err
}

func readOnlyPost(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	switch r.URL.Path {
	case "/api/dlp/compile", "/api/dlp/evaluate", "/api/discovery/catalog/compile", "/api/discovery/catalog/evaluate", "/api/ai-governance/validate", "/api/ai-governance/systems/validate":
		return true
	}
	return false
}

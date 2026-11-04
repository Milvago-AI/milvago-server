package app

import (
	"net/http"

	"github.com/jackc/pgx/v5"
)

// failTransaction releases database resources before client-controlled error I/O.
// Preserve the original failure, just as the deferred rollback previously did.
func (a *App) failTransaction(w http.ResponseWriter, r *http.Request, tx pgx.Tx, err error) {
	_ = tx.Rollback(r.Context())
	a.fail(w, err)
}

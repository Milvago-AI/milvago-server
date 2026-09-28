package app

import "net/http"

// Public preferences contain no account, organization or authorization data.
func (a *App) bootstrap(w http.ResponseWriter, r *http.Request) {
	var language string
	if e := a.db.QueryRow(r.Context(), "SELECT default_language FROM app_config").Scan(&language); e != nil {
		a.fail(w, e)
		return
	}
	reply(w, 200, map[string]any{"default_language": language, "edition": Edition, "demo_read_only": a.config.DemoReadOnly})
}

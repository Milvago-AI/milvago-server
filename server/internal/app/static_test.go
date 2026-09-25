package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type staticCase struct {
	path   string
	status int
	body   string
	cache  string
}

func assertStaticCase(t *testing.T, app *App, tc staticCase) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.URL.Path = tc.path
	recorder := httptest.NewRecorder()
	app.static(recorder, request)
	if recorder.Code != tc.status {
		t.Fatalf("status %d, want %d", recorder.Code, tc.status)
	}
	if strings.Contains(recorder.Body.String(), "private fixture") {
		t.Fatal("static handler served a file outside its root")
	}
	if tc.body != "" && !strings.Contains(recorder.Body.String(), tc.body) {
		t.Fatalf("response does not contain %q", tc.body)
	}
	if tc.cache != "" && recorder.Header().Get("Cache-Control") != tc.cache {
		t.Fatalf("Cache-Control = %q, want %q", recorder.Header().Get("Cache-Control"), tc.cache)
	}
}

func assertStaticSymlink(t *testing.T, app *App, parent, staticDir string) {
	t.Helper()
	if err := os.Symlink(filepath.Join(parent, "private.txt"), filepath.Join(staticDir, "escape.txt")); err == nil {
		request := httptest.NewRequest(http.MethodGet, "/escape.txt", nil)
		recorder := httptest.NewRecorder()
		app.static(recorder, request)
		if strings.Contains(recorder.Body.String(), "private fixture") {
			t.Fatal("static handler followed a link outside its root")
		}
	}
}

func TestStaticConfinesRequests(t *testing.T) {
	parent := t.TempDir()
	staticDir := filepath.Join(parent, "site")
	if err := os.Mkdir(staticDir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		filepath.Join(staticDir, "index.html"): "application shell",
		filepath.Join(staticDir, "app.js"):     "static asset",
		filepath.Join(parent, "private.txt"):   "private fixture",
	} {
		if err := os.WriteFile(name, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	app := &App{config: Config{StaticDir: staticDir}}
	for _, tc := range []staticCase{
		{"/app.js", http.StatusOK, "static asset", ""},
		{"/nested/page", http.StatusOK, "application shell", "no-store"},
		{"/../private.txt", http.StatusNotFound, "", ""},
		{"/..\\private.txt", http.StatusNotFound, "", ""},
	} {
		t.Run(tc.path, func(t *testing.T) { assertStaticCase(t, app, tc) })
	}
	assertStaticSymlink(t, app, parent, staticDir)
}

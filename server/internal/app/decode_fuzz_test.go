package app

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// FuzzDecode exercises decode() (app.go), the single JSON body reader shared by every
// unauthenticated and device-authenticated route in the product (enrollment, ingestion,
// policy, completions...). The request shape here mirrors the ingestion batch body
// ({"events":[...]}, see shadow_endpoint.go's v2IngestRequest) since that is the route an
// unauthenticated-until-enrolled or already-compromised device reaches most often, but
// decode() itself never looks past Content-Type and the raw bytes: nothing here depends
// on V2Event's own fields being fuzzed, only on decode's Content-Type/body handling.
//
// Invariant: decode never panics on any Content-Type or body, and any failure it reports
// is always the documented apiError shape with status 400 or 415 -- never a bare error a
// caller's a.fail would turn into an opaque 500.
func FuzzDecode(f *testing.F) {
	f.Add("application/json", []byte(`{"events":[]}`))
	f.Add("application/json", []byte(`{}`))
	f.Add("application/json; charset=utf-8", []byte(`{"events":[{"id":"x"}]}`))
	f.Add("text/plain", []byte(`{}`))
	f.Add("", []byte(`{}`))
	f.Add("application/json", []byte(``))
	f.Add("application/json", []byte(`{`))
	f.Add("application/json", []byte(`[]`))
	f.Add("application/json", []byte(`{"events":[]} {}`))
	f.Add("application/json", []byte(`{"unknown_field":1}`))
	f.Add("application/json", bytes.Repeat([]byte(`{"a":`), 5000))

	f.Fuzz(func(t *testing.T, contentType string, body []byte) {
		var target struct {
			Events []V2Event `json:"events"`
		}
		r := httptest.NewRequest(http.MethodPost, "/v2/events", bytes.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		w := httptest.NewRecorder()

		err := decode(w, r, &target)
		if err == nil {
			return
		}
		var ae apiError
		if !errors.As(err, &ae) {
			t.Fatalf("decode returned a non-apiError error: %v", err)
		}
		if ae.status != 400 && ae.status != 415 {
			t.Fatalf("decode returned unexpected status %d for error %q", ae.status, err.Error())
		}
	})
}

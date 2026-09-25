//go:build hpa_lab

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type hpaDevice struct {
	ID           string `json:"id"`
	Organization string `json:"organization"`
	Credential   string `json:"credential"`
	Export       bool   `json:"export"`
	CheckOnly    bool   `json:"check_only"`
}
type hpaOrganization struct {
	ID      string `json:"id"`
	Session string `json:"session"`
	CSRF    string `json:"csrf"`
}
type hpaFixture struct {
	Edition       string            `json:"edition"`
	Root          string            `json:"root"`
	Devices       []hpaDevice       `json:"devices"`
	Organizations []hpaOrganization `json:"organizations"`
}

// HPALabFixture is absent from every production build. Even this test-only binary
// refuses any database outside the explicitly named synthetic kind laboratory.
func HPALabFixture(ctx context.Context, c Config, action, output string) error {
	u, err := url.Parse(c.MigrationURL)
	if err != nil || u.Path != "/milvago_hpa_"+Edition || os.Getenv("MILVAGO_HPA_LAB") != "milvago-hpa-test" {
		return errors.New("fixture requires the isolated HPA laboratory database")
	}
	pool, err := pgxpool.New(ctx, c.MigrationURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	var result any
	switch action {
	case "seed":
		result, err = seedHPALab(ctx, pool)
	case "exports", "disable-exports":
		err = configureHPALabExports(ctx, pool, action == "exports")
		result = map[string]any{"edition": Edition, "enabled": action == "exports"}
	case "report":
		result, err = reportHPALab(ctx, pool)
	default:
		return errors.New("unknown fixture action")
	}
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		return err
	}
	return os.WriteFile(output, raw, 0600)
}

func seedHPALab(ctx context.Context, pool *pgxpool.Pool) (hpaFixture, error) {
	out := hpaFixture{Edition: Edition}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	var count int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM organizations").Scan(&count); err != nil {
		return out, err
	}
	if count != 1 {
		return out, errors.New("seed requires a freshly migrated laboratory")
	}
	if err = tx.QueryRow(ctx, "SELECT id FROM organizations LIMIT 1").Scan(&out.Root); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, "SELECT set_config('milvago.organization_id',$1,true)", out.Root); err != nil {
		return out, err
	}
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM devices").Scan(&count); err != nil {
		return out, err
	}
	if count != 0 {
		return out, errors.New("seed refuses existing devices")
	}
	var user string
	if err = tx.QueryRow(ctx, "INSERT INTO users(subject,email,display_name) VALUES('hpa-synthetic-owner','owner@example.test','Synthetic operator') RETURNING id").Scan(&user); err != nil {
		return out, err
	}
	orgCount := 1
	if Edition == "commercial" {
		orgCount = 65
	}
	for i := 0; i < orgCount; i++ {
		org := out.Root
		if i > 0 {
			if err = tx.QueryRow(ctx, "INSERT INTO organizations(name,parent_id) VALUES($1,$2) RETURNING id", fmt.Sprintf("Synthetic partition %03d", i), out.Root).Scan(&org); err != nil {
				return out, err
			}
		}
		if _, err = tx.Exec(ctx, "SELECT set_config('milvago.organization_id',$1,true)", org); err != nil {
			return out, err
		}
		if err = seedBuiltinRoles(ctx, tx, org); err != nil {
			return out, err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO settings(organization_id) VALUES($1) ON CONFLICT DO NOTHING", org); err != nil {
			return out, err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO policies(organization_id) VALUES($1) ON CONFLICT DO NOTHING", org); err != nil {
			return out, err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')", org, user); err != nil {
			return out, err
		}
		session, csrf := randomToken(), randomToken()
		if _, err = tx.Exec(ctx, "INSERT INTO sessions(token_hash,user_id,organization_id,csrf_token,encrypted_tokens,mfa,expires_at,identity_expires_at,mfa_verified_at) VALUES($1,$2,$3,$4,$5,true,clock_timestamp()+interval '24 hours',clock_timestamp()+interval '24 hours',clock_timestamp())", hash(session), user, org, csrf, []byte("synthetic-lab-session")); err != nil {
			return out, err
		}
		out.Organizations = append(out.Organizations, hpaOrganization{org, session, csrf})
		devices := 1
		if i == 0 {
			devices = 129
		}
		for j := 0; j < devices; j++ {
			d := hpaDevice{Organization: org, Credential: randomToken(), Export: i > 0, CheckOnly: i == 0 && j == 128}
			if err = tx.QueryRow(ctx, "INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,kind) VALUES($1,$2,$3,'windows','0.5.11','approved','browser') RETURNING id", org, hash(d.Credential), fmt.Sprintf("synthetic-endpoint-%03d-%03d", i, j)).Scan(&d.ID); err != nil {
				return out, err
			}
			out.Devices = append(out.Devices, d)
		}
	}
	return out, tx.Commit(ctx)
}

func configureHPALabExports(ctx context.Context, pool *pgxpool.Pool, enabled bool) error {
	if Edition != "commercial" {
		return errors.New("exports require Enterprise")
	}
	endpoint := os.Getenv("FIXTURE_COLLECTOR_URL")
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.Hostname() != "collector-proxy" {
		return errors.New("fixture destination must be the isolated collector-proxy")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(7069204)"); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, "SELECT id FROM organizations WHERE parent_id IS NOT NULL ORDER BY id")
	if err != nil {
		return err
	}
	var orgs []string
	for rows.Next() {
		var org string
		if err = rows.Scan(&org); err != nil {
			rows.Close()
			return err
		}
		orgs = append(orgs, org)
	}
	rows.Close()
	if rows.Err() != nil {
		return rows.Err()
	}
	if len(orgs) != 64 {
		return errors.New("exports require exactly 64 synthetic partitions")
	}
	raw, _ := json.Marshal(map[string]any{"inherit": false, "destinations": []any{map[string]any{"id": "grafana", "enabled": enabled, "endpoint": endpoint, "event_filter": "all", "metrics": false, "shadow_events": true, "audit": false}, map[string]any{"id": "siem", "enabled": false, "endpoint": "", "event_filter": "security", "metrics": false, "shadow_events": true, "audit": false}}})
	for _, org := range orgs {
		if _, err = tx.Exec(ctx, "SELECT set_config('milvago.organization_id',$1,true)", org); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO observability_settings(organization_id,configuration) VALUES($1,$2) ON CONFLICT(organization_id) DO UPDATE SET configuration=excluded.configuration,revision=observability_settings.revision+1,updated_at=clock_timestamp()", org, raw); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func reportHPALab(ctx context.Context, pool *pgxpool.Pool) (any, error) {
	rows, err := pool.Query(ctx, "SELECT id FROM organizations ORDER BY id")
	if err != nil {
		return nil, err
	}
	var orgs []string
	for rows.Next() {
		var org string
		if err = rows.Scan(&org); err != nil {
			rows.Close()
			return nil, err
		}
		orgs = append(orgs, org)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	result := map[string]any{"edition": Edition, "at": time.Now().UTC(), "organizations": map[string]any{}}
	for _, org := range orgs {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return nil, err
		}
		value, err := reportHPATenant(ctx, tx, org)
		_ = tx.Rollback(ctx)
		if err != nil {
			return nil, err
		}
		result["organizations"].(map[string]any)[org] = value
	}
	return result, nil
}
func reportHPATenant(ctx context.Context, tx pgx.Tx, org string) (any, error) {
	if _, err := tx.Exec(ctx, "SELECT set_config('milvago.organization_id',$1,true)", org); err != nil {
		return nil, err
	}
	var events []string
	rows, err := tx.Query(ctx, "SELECT organization_id::text||'/'||device_id::text||'/'||id::text FROM shadow_events ORDER BY id")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		events = append(events, id)
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	value := map[string]any{"event_keys": events}
	if Edition == "commercial" {
		var delivered []string
		rows, err = tx.Query(ctx, "SELECT organization_id::text||'/'||device_id||'/'||record_id::text FROM observability_deliveries WHERE stream='shadow' AND sink='grafana' ORDER BY record_id")
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			delivered = append(delivered, id)
		}
		rows.Close()
		if rows.Err() != nil {
			return nil, rows.Err()
		}
		value["delivered_keys"] = delivered
	}
	return value, nil
}

package app

import (
	"context"
	"encoding/json"
	"testing"
)

// GET /api/devices has four consumers -- the device page, the overview badge, the two
// group dialogs and the Enterprise MCP tool -- and had no server-side test of its
// response shape at all. The filters and the page moved into SQL on 2026-09-21; this
// pins the contract that move had to preserve.
//
// Two facts here are easy to break and impossible to see from the console:
// `fleet`, `pending` and `platforms` describe the WHOLE fleet, never the filtered page,
// and `exclude_group_id` KEEPS the machines that belong to no group -- which is the whole
// point of the "devices you can add to this group" dialog.
func TestDeviceListingFacetsAndFilters(t *testing.T) {
	p := newProjectionFixture(t)
	ctx := context.Background()

	tx, e := tenantTx(ctx, p.a.db, p.org)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	seed := func(platform, status string, group *string) string {
		t.Helper()
		var id string
		if e := tx.QueryRow(ctx, "INSERT INTO devices(organization_id,credential_hash,hostname,platform,version,status,group_id) VALUES($1,$2,'',$3,'0.5.0',$4,$5) RETURNING id",
			p.org, hash(randomToken()), platform, status, group).Scan(&id); e != nil {
			t.Fatal(e)
		}
		return id
	}
	// The fixture already carries one approved device on platform "test", in p.group.
	// The revoked linux machine is deliberate: revoked devices are still rows of the
	// listing, so `fleet` counts them (four, not three) and `platforms` lists linux even
	// though no live device runs it. Excluding them would send a fleet whose every machine
	// was revoked back to the first-installation screen and hide its history.
	seed("windows", "approved", &p.group)
	seed("windows", "pending", nil)
	seed("linux", "revoked", nil)
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}

	type page struct {
		Items     []map[string]any `json:"items"`
		Total     int              `json:"total"`
		Fleet     int              `json:"fleet"`
		Pending   int              `json:"pending"`
		Limit     int              `json:"limit"`
		Offset    int              `json:"offset"`
		Platforms []string         `json:"platforms"`
	}
	get := func(t *testing.T, query string) page {
		t.Helper()
		w := p.as("owner", "GET", "/api/devices"+query, nil)
		if w.Code != 200 {
			t.Fatalf("GET /api/devices%s answered %d: %s", query, w.Code, w.Body.String())
		}
		var out page
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		return out
	}

	t.Run("facets describe the whole fleet, not the filtered page", func(t *testing.T) {
		all := get(t, "")
		if len(all.Items) != 4 || all.Total != 4 || all.Fleet != 4 {
			t.Fatalf("expected the four seeded devices, got %d items, total %d, fleet %d", len(all.Items), all.Total, all.Fleet)
		}
		if all.Pending != 1 {
			t.Fatalf("pending over the whole fleet = %d, want 1", all.Pending)
		}
		if len(all.Platforms) != 3 {
			t.Fatalf("platforms over the whole fleet = %v, want three", all.Platforms)
		}
		// Narrowing to one platform must not narrow either facet.
		one := get(t, "?platform=linux")
		if one.Total != 1 || len(one.Items) != 1 {
			t.Fatalf("platform filter kept %d rows, total %d, want 1 and 1", len(one.Items), one.Total)
		}
		if one.Fleet != all.Fleet {
			t.Fatalf("fleet followed the filter: %d, want %d", one.Fleet, all.Fleet)
		}
		if one.Pending != all.Pending {
			t.Fatalf("pending followed the filter: %d, want %d", one.Pending, all.Pending)
		}
		if len(one.Platforms) != len(all.Platforms) {
			t.Fatalf("platforms followed the filter: %v, want %v", one.Platforms, all.Platforms)
		}
	})

	t.Run("status filter", func(t *testing.T) {
		if got := get(t, "?status=pending"); got.Total != 1 || len(got.Items) != 1 {
			t.Fatalf("status=pending kept %d rows, total %d, want 1 and 1", len(got.Items), got.Total)
		}
	})

	t.Run("group_id keeps only that group", func(t *testing.T) {
		got := get(t, "?group_id="+p.group)
		if got.Total != 2 {
			t.Fatalf("group_id kept %d rows, want the two devices in the group", got.Total)
		}
		for _, item := range got.Items {
			if item["group_id"] != p.group {
				t.Fatalf("group_id returned a device from another group: %v", item["group_id"])
			}
		}
	})

	t.Run("exclude_group_id keeps the ungrouped machines", func(t *testing.T) {
		got := get(t, "?exclude_group_id="+p.group)
		if got.Total != 2 {
			t.Fatalf("exclude_group_id kept %d rows, want the two ungrouped devices; a SQL <> would have dropped them through three-valued logic", got.Total)
		}
		for _, item := range got.Items {
			if item["group_id"] == p.group {
				t.Fatal("exclude_group_id returned a device from the excluded group")
			}
		}
	})

	t.Run("total stays exact past the end of the page", func(t *testing.T) {
		got := get(t, "?limit=1&offset=99")
		if got.Total != 4 {
			t.Fatalf("total past the last page = %d, want 4: the bounded pager depends on it", got.Total)
		}
		if len(got.Items) != 0 {
			t.Fatalf("offset past the end returned %d rows", len(got.Items))
		}
	})

	t.Run("a page is cut without losing the count", func(t *testing.T) {
		got := get(t, "?limit=2")
		if len(got.Items) != 2 || got.Total != 4 {
			t.Fatalf("limit=2 returned %d rows with total %d, want 2 and 4", len(got.Items), got.Total)
		}
	})

	t.Run("device_id scopes the rows, never the facets", func(t *testing.T) {
		got := get(t, "?device_id="+p.device)
		if got.Total != 1 || len(got.Items) != 1 {
			t.Fatalf("device_id kept %d rows, total %d, want 1 and 1", len(got.Items), got.Total)
		}
		if got.Fleet != 4 || len(got.Platforms) != 3 || got.Pending != 1 {
			t.Fatalf("facets under device_id: fleet %d, platforms %v, pending %d; want the fleet's four devices, three platforms and one pending device", got.Fleet, got.Platforms, got.Pending)
		}
		// A device the URL still names but the fleet no longer holds -- deleted, or
		// another organization's. The console reads `fleet` as "is there a fleet at all",
		// so this must come back as a populated fleet with no match, never as the "ready
		// for your first device" screen and its installer download.
		gone := get(t, "?device_id=00000000-0000-4000-8000-0000000000ff")
		if gone.Total != 0 || len(gone.Items) != 0 {
			t.Fatalf("an unknown device_id kept %d rows, total %d, want none", len(gone.Items), gone.Total)
		}
		if gone.Fleet != 4 || len(gone.Platforms) != 3 || gone.Pending != 1 {
			t.Fatalf("facets under an unknown device_id: fleet %d, platforms %v, pending %d; want the whole fleet", gone.Fleet, gone.Platforms, gone.Pending)
		}
	})

	t.Run("the overview carries the same fleet-wide pending count", func(t *testing.T) {
		// The overview's to-do badge used to fetch this listing with limit=1 for the one
		// figure it needed; it now reads `pending_devices` from /api/overview, which must
		// agree with `pending` here.
		w := p.as("owner", "GET", "/api/overview", nil)
		if w.Code != 200 {
			t.Fatalf("GET /api/overview answered %d: %s", w.Code, w.Body.String())
		}
		var overview struct {
			Devices        int `json:"devices"`
			PendingDevices int `json:"pending_devices"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &overview); e != nil {
			t.Fatal(e)
		}
		if overview.Devices != 4 || overview.PendingDevices != 1 {
			t.Fatalf("overview devices %d, pending_devices %d; want 4 and 1", overview.Devices, overview.PendingDevices)
		}
	})

	t.Run("the sealed hostname filter still answers", func(t *testing.T) {
		// The fixture's device carries a sealed hostname; the others were seeded blank.
		// hostname and os_user have no SQL form, so this is the path that still opens
		// every envelope -- it must keep working, and it must keep its exact count.
		got := get(t, "?query="+p.s.host[:8])
		if got.Total != 1 || len(got.Items) != 1 {
			t.Fatalf("query on the sealed hostname kept %d rows, total %d, want 1 and 1", len(got.Items), got.Total)
		}
	})
}

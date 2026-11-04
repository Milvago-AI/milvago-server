package app

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestDataReadDLPParentSnapshotIsolation(t *testing.T) {
	f := newObservabilityFixture(t)
	ctx := context.Background()
	tx, err := tenantTx(ctx, f.a.db, f.org)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	plain, err := f.a.readDLP(ctx, tx, f.org, "endpoint", "organization", f.org, 0)
	if err != nil {
		t.Fatal(err)
	}
	counted := &policyCountingTx{Tx: tx}
	cachedCtx := dlpReadPageContext(ctx)
	first, err := f.a.readDLP(cachedCtx, counted, f.org, "endpoint", "organization", f.org, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plain, first) {
		t.Fatal("memo changed effective DLP settings")
	}
	reads := counted.calls
	first.Capabilities["changed"] = true
	if len(first.Policy.Rules) > 0 {
		first.Policy.Rules[0].Condition = json.RawMessage(`{"op":"changed"}`)
	}
	second, err := f.a.readDLP(cachedCtx, counted, f.org, "endpoint", "organization", f.org, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plain, second) {
		t.Fatalf("snapshot changed another device's parent policy: %s", dataReadDifference(reflect.ValueOf(plain), reflect.ValueOf(second), "settings"))
	}
	if counted.calls != reads {
		t.Fatal("parent policy queried again within one page")
	}
	if _, ok := cachedCtx.Value(dlpReadMemoKey{}).(*dlpReadMemo).get([4]string{missingGroupID, "endpoint", "organization", f.org}); ok {
		t.Fatal("snapshot crossed tenant key")
	}
	_, err = f.a.readDLP(cachedCtx, counted, f.org, "endpoint", "organization", f.org, 25)
	if err == nil {
		t.Fatal("memo bypassed ancestry depth limit")
	}
	// A new page has no values from its predecessor.
	if _, ok := dlpReadPageContext(ctx).Value(dlpReadMemoKey{}).(*dlpReadMemo).get([4]string{f.org, "endpoint", "organization", f.org}); ok {
		t.Fatal("snapshot survived request boundary")
	}
}

func dataReadDifference(a, b reflect.Value, path string) string {
	if !a.IsValid() || !b.IsValid() {
		return path + ": missing value"
	}
	if reflect.DeepEqual(a.Interface(), b.Interface()) {
		return ""
	}
	switch a.Kind() {
	case reflect.Struct:
		for i := 0; i < a.NumField(); i++ {
			if d := dataReadDifference(a.Field(i), b.Field(i), path+"."+a.Type().Field(i).Name); d != "" {
				return d
			}
		}
	case reflect.Slice, reflect.Array:
		if a.Kind() == reflect.Slice && a.IsNil() != b.IsNil() {
			return fmt.Sprintf("%s: nil=%v/%v len=%d/%d", path, a.IsNil(), b.IsNil(), a.Len(), b.Len())
		}
		if a.Len() != b.Len() {
			return fmt.Sprintf("%s: len=%d/%d", path, a.Len(), b.Len())
		}
		for i := 0; i < a.Len(); i++ {
			if d := dataReadDifference(a.Index(i), b.Index(i), fmt.Sprintf("%s[%d]", path, i)); d != "" {
				return d
			}
		}
	case reflect.Pointer:
		if a.IsNil() || b.IsNil() {
			return path + ": nil pointer changed"
		}
		return dataReadDifference(a.Elem(), b.Elem(), path)
	case reflect.Map:
		for _, key := range a.MapKeys() {
			if d := dataReadDifference(a.MapIndex(key), b.MapIndex(key), path+"."+fmt.Sprint(key.Interface())); d != "" {
				return d
			}
		}
	}
	return path + ": values differ"
}

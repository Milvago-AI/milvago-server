package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// syncPublicIdentity keeps the browser client and realm issuer aligned with the
// instance URL. It uses the private identity service; public admin routes stay closed.
func (a *App) syncPublicIdentity(ctx context.Context, origin string) error {
	if !validOrigin(origin) {
		return bad("Public URL must be an HTTP or HTTPS origin.")
	}
	admin, err := a.identityAdmin(ctx)
	if err != nil {
		return err
	}
	path := "/clients?clientId=" + url.QueryEscape(a.config.ClientID)
	status, _, raw, err := admin.call(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiError{502, "identity_unavailable", "Could not read the identity client."}
	}
	var clients []map[string]any
	if json.Unmarshal(raw, &clients) != nil {
		return apiError{502, "identity_unavailable", "Invalid identity client response."}
	}
	var client map[string]any
	for _, candidate := range clients {
		if candidate["clientId"] == a.config.ClientID {
			client = candidate
			break
		}
	}
	id, _ := client["id"].(string)
	if id == "" {
		return apiError{502, "identity_unavailable", "The identity client is missing."}
	}
	client["redirectUris"] = []string{origin + "/auth/callback"}
	client["webOrigins"] = []string{origin}
	attributes, _ := client["attributes"].(map[string]any)
	if attributes == nil {
		attributes = map[string]any{}
	}
	attributes["post.logout.redirect.uris"] = origin + "/*"
	client["attributes"] = attributes
	status, _, _, err = admin.call(ctx, http.MethodPut, "/clients/"+url.PathEscape(id), client)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return apiError{502, "identity_unavailable", "Could not update the identity client."}
	}

	if strings.HasPrefix(a.config.Issuer, a.config.AppURL+"/realms/") {
		status, _, raw, err = admin.call(ctx, http.MethodGet, "", nil)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiError{502, "identity_unavailable", "Could not read the identity realm."}
		}
		var realm map[string]any
		if json.Unmarshal(raw, &realm) != nil {
			return apiError{502, "identity_unavailable", "Invalid identity realm response."}
		}
		realmAttributes, _ := realm["attributes"].(map[string]any)
		if realmAttributes == nil {
			realmAttributes = map[string]any{}
		}
		realmAttributes["frontendUrl"] = origin
		realm["attributes"] = realmAttributes
		status, _, _, err = admin.call(ctx, http.MethodPut, "", realm)
		if err != nil {
			return err
		}
		if status != http.StatusNoContent {
			return apiError{502, "identity_unavailable", "Could not update the identity realm URL."}
		}
		status, _, raw, err = admin.call(ctx, http.MethodGet, "", nil)
		if err != nil {
			return err
		}
		realm = nil
		if status != http.StatusOK || json.Unmarshal(raw, &realm) != nil {
			return apiError{502, "identity_unavailable", "Could not verify the identity realm URL."}
		}
		confirmed, _ := realm["attributes"].(map[string]any)
		if confirmed["frontendUrl"] != origin {
			return apiError{502, "identity_unavailable", "The identity realm URL was not applied."}
		}
	}
	status, _, raw, err = admin.call(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK || json.Unmarshal(raw, &clients) != nil {
		return apiError{502, "identity_unavailable", "Could not verify the identity client URL."}
	}
	for _, item := range clients {
		if item["clientId"] != a.config.ClientID {
			continue
		}
		redirects, _ := item["redirectUris"].([]any)
		if len(redirects) == 1 && redirects[0] == origin+"/auth/callback" {
			return nil
		}
	}
	return apiError{502, "identity_unavailable", "The identity client URL was not applied."}
}

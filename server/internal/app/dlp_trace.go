package app

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"unicode"

	"github.com/jackc/pgx/v5"
)

var dlpDecisionOutcomes = []string{"unavailable", "simulated", "matched", "blocked", "overridden", "prepared", "final_blocked", "observed", "cancelled", "observed_after_send"}
var dlpDeliveries = []string{"not_sent", "prepared", "observed", "unknown", "cancelled"}

// DLPTrace contains only engine decisions and a signed policy identity. Original
// prompt values and detector evidence never belong in the metadata journal.
type DLPTrace struct {
	Fingerprint string        `json:"fingerprint"`
	Action      string        `json:"action"`
	Delivery    string        `json:"delivery"`
	Decisions   []DLPDecision `json:"decisions"`
}

func validDLPTrace(trace *DLPTrace) bool {
	if trace == nil {
		return true
	}
	if !validDLPFingerprint(trace.Fingerprint) || !slices.Contains([]string{"observe", "block", "transform", "review"}, trace.Action) || !slices.Contains(dlpDeliveries, trace.Delivery) || len(trace.Decisions) < 1 || len(trace.Decisions) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, d := range trace.Decisions {
		if !dlpIdentifier(d.RuleID) || seen[d.RuleID] || d.RuleRevision < 1 || d.RuleRevision > 9007199254740991 || len(d.RuleName) < 1 || len(d.RuleName) > 100 || slices.ContainsFunc([]rune(d.RuleName), unicode.IsControl) || !slices.Contains([]string{"active", "simulation"}, d.Mode) || !slices.Contains([]string{"true", "unknown"}, d.Condition) || !slices.Contains([]string{"true", "unknown"}, d.Scope) || !slices.Contains([]string{"observe", "warn", "block", "mask", "replace"}, d.Consequence) || !slices.Contains(dlpDecisionOutcomes, d.Outcome) || d.Occurrences < 0 || d.Occurrences > 2048 {
			return false
		}
		seen[d.RuleID] = true
	}
	return true
}

func dlpIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 100 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func (a *App) validateDLPEvent(r *http.Request, tx pgx.Tx, state *ingestBatchState, v V2Event) (DLPPolicy, error) {
	var policy DLPPolicy
	if v.DLP == nil {
		return policy, nil
	}
	if !validDLPTrace(v.DLP) || v.Kind != "prompt" {
		return policy, bad("Invalid DLP event metadata.")
	}
	key := v.DLP.Fingerprint + ":" + strconv.FormatInt(v.PolicyRevision, 10)
	if cached, ok := state.dlpPolicies[key]; ok {
		policy = cached
	} else {
		var raw []byte
		err := tx.QueryRow(r.Context(), `SELECT p.policy FROM dlp_policy_snapshots p JOIN dlp_device_policy_history h USING(organization_id,fingerprint) WHERE h.device_id=$1 AND h.fingerprint=$2 AND h.revision=$3`, state.device, v.DLP.Fingerprint, v.PolicyRevision).Scan(&raw)
		if err == pgx.ErrNoRows {
			return policy, bad("The DLP policy was not delivered to this installation.")
		}
		if err != nil {
			return policy, err
		}
		if json.Unmarshal(raw, &policy) != nil || policy.Domain != "endpoint" || !policy.Journal {
			return policy, bad("DLP journaling was not authorized by the signed policy.")
		}
		if state.dlpPolicies == nil {
			state.dlpPolicies = map[string]DLPPolicy{}
		}
		state.dlpPolicies[key] = policy
	}
	for _, decision := range v.DLP.Decisions {
		index := slices.IndexFunc(policy.Rules, func(rule DLPRule) bool { return rule.ID == decision.RuleID })
		if index < 0 {
			return policy, bad("Unknown historical DLP rule.")
		}
		rule := policy.Rules[index]
		var effect struct {
			Action string `json:"action"`
		}
		if json.Unmarshal(rule.Consequence, &effect) != nil || rule.Revision != decision.RuleRevision || rule.Name != decision.RuleName || rule.Mode != decision.Mode || effect.Action != decision.Consequence {
			return policy, bad("DLP attribution does not match the delivered rule revision.")
		}
	}
	return policy, nil
}

// The same frozen attribution is projected into lists, message bubbles, details
// and exports. A historical row without evidence stays unattributed.
const dlpTraceProjection = `(SELECT jsonb_build_object('fingerprint',dd.policy_fingerprint,'action',dd.action,'delivery',dd.delivery,'decisions',dd.decisions) FROM dlp_decisions dd WHERE dd.organization_id=e.organization_id AND dd.device_id=e.device_id AND dd.event_id=e.id AND dd.expires_at>now() ORDER BY dd.occurred_at,dd.id LIMIT 1)`

const dlpHasEvidenceProjection = `EXISTS(SELECT 1 FROM dlp_decisions dd WHERE dd.organization_id=e.organization_id AND dd.device_id=e.device_id AND dd.event_id=e.id AND dd.expires_at>now())`

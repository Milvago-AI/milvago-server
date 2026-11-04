package app

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
)

type dlpReadMemoKey struct{}
type dlpReadMemo struct {
	values map[[4]string]DLPSettings
	bytes  int
}

// A deployment page may reuse its parent policies. Detached copies preserve the
// exact expression bytes and prevent a caller's normalization from changing the
// next device. Values never outlive the request or cross its tenant keys.
func dlpReadPageContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, dlpReadMemoKey{}, &dlpReadMemo{values: map[[4]string]DLPSettings{}})
}
func (memo *dlpReadMemo) get(key [4]string) (DLPSettings, bool) {
	if memo == nil {
		return DLPSettings{}, false
	}
	out, ok := memo.values[key]
	if !ok {
		return DLPSettings{}, false
	}
	return cloneDLPReadSettings(out), true
}
func (memo *dlpReadMemo) put(key [4]string, out DLPSettings) {
	if memo == nil || len(memo.values) >= 128 {
		return
	}
	raw, err := json.Marshal(out)
	size := len(raw) + dlpReadExpressionBytes(out.Policy)
	if err != nil || memo.bytes+size > 8<<20 {
		return
	}
	memo.values[key] = cloneDLPReadSettings(out)
	memo.bytes += size
}
func cloneDLPReadRule(rule DLPRule) DLPRule {
	rule.Condition = slices.Clone(rule.Condition)
	rule.Scope = slices.Clone(rule.Scope)
	rule.Consequence = slices.Clone(rule.Consequence)
	if rule.Application != nil {
		application := *rule.Application
		application.IDs = slices.Clone(application.IDs)
		rule.Application = &application
	}
	return rule
}
func cloneDLPReadPolicy(policy DLPPolicy) DLPPolicy {
	policy.Detectors = slices.Clone(policy.Detectors)
	for i := range policy.Detectors {
		policy.Detectors[i].Definition = slices.Clone(policy.Detectors[i].Definition)
	}
	policy.Rules = slices.Clone(policy.Rules)
	for i := range policy.Rules {
		policy.Rules[i] = cloneDLPReadRule(policy.Rules[i])
	}
	return policy
}
func cloneDLPReadSettings(out DLPSettings) DLPSettings {
	out.DefaultRuleIDs = slices.Clone(out.DefaultRuleIDs)
	out.Capabilities = maps.Clone(out.Capabilities)
	out.ScopeOptions.Browsers = slices.Clone(out.ScopeOptions.Browsers)
	out.ScopeOptions.Services = slices.Clone(out.ScopeOptions.Services)
	out.ScopeOptions.Applications = slices.Clone(out.ScopeOptions.Applications)
	out.Policy = cloneDLPReadPolicy(out.Policy)
	return out
}
func dlpReadExpressionBytes(policy DLPPolicy) int {
	size := 0
	for _, v := range policy.Detectors {
		size += len(v.Definition)
	}
	for _, v := range policy.Rules {
		size += len(v.Condition) + len(v.Scope) + len(v.Consequence)
	}
	return size
}

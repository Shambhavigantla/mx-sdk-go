package drwa

// TokenSummary describes the additive DRWA token data surfaced to SDK clients.
type TokenSummary struct {
	Regulated          bool
	PolicyID           string
	TokenPolicyVersion uint32
	GlobalPause        bool
	StrictAuditorMode  bool
}

func GetPolicySummary(payload map[string]any) (*TokenSummary, bool) {
	if payload == nil {
		return nil, false
	}

	raw, ok := payload["drwa"].(map[string]any)
	if !ok {
		return nil, false
	}

	summary := &TokenSummary{
		Regulated:         boolValue(raw, "regulated", "enabled", "isDrwa"),
		PolicyID:          stringValue(raw, "policyId"),
		GlobalPause:       boolValue(raw, "globalPause"),
		StrictAuditorMode: boolValue(raw, "strictAuditorMode"),
	}

	if version, ok := uint32Value(raw, "tokenPolicyVersion"); ok {
		summary.TokenPolicyVersion = version
	}

	return summary, true
}

func IsDRWAToken(payload map[string]any) bool {
	summary, ok := GetPolicySummary(payload)
	return ok && summary.Regulated
}

func boolValue(raw map[string]any, keys ...string) bool {
	for _, key := range keys {
		if value, ok := raw[key].(bool); ok {
			return value
		}
	}
	return false
}

func stringValue(raw map[string]any, key string) string {
	if value, ok := raw[key].(string); ok {
		return value
	}
	return ""
}

func uint32Value(raw map[string]any, key string) (uint32, bool) {
	switch value := raw[key].(type) {
	case uint32:
		return value, true
	case uint64:
		return uint32(value), true
	case int:
		return uint32(value), true
	case int32:
		return uint32(value), true
	case int64:
		return uint32(value), true
	case float64:
		return uint32(value), true
	default:
		return 0, false
	}
}

package drwa

import (
	"regexp"
	"strings"
)

const denialPrefix = "DRWA_"

var denialPattern = regexp.MustCompile(`\bDRWA_[A-Z0-9_]+\b`)

// knownDenialCodes maps every protocol error code (as emitted by the Go
// enforcement gate) and its known legacy aliases to a single stable SDK code.
// Legacy aliases are preserved for backwards-compatible parsing of older
// on-chain messages, but they resolve to the same SDK code as the canonical
// protocol identifier so downstream analytics are not fragmented.
var knownDenialCodes = map[string]string{
	// Canonical protocol codes (emitted by mx-chain-vm-common-go gate).
	"DRWA_KYC_REQUIRED":           "kyc_required",
	"DRWA_AML_BLOCKED":            "aml_blocked",
	"DRWA_JURISDICTION_BLOCKED":   "jurisdiction_blocked",
	"DRWA_INVESTOR_CLASS_BLOCKED": "investor_class_blocked",
	"DRWA_TOKEN_PAUSED":           "token_paused",
	"DRWA_TRANSFER_LOCKED":        "transfer_locked",
	"DRWA_RECEIVE_LOCKED":         "receive_locked",
	"DRWA_AUDITOR_REQUIRED":       "auditor_required",
	"DRWA_ASSET_EXPIRED":          "asset_expired",
	// Legacy aliases — map to the same SDK code as the canonical form above.
	"DRWA_KYB_REQUIRED":              "kyc_required",              // alias of KYC_REQUIRED
	"DRWA_TOKEN_EXPIRED":             "asset_expired",             // alias of ASSET_EXPIRED
	"DRWA_GLOBAL_PAUSE":              "token_paused",              // alias of TOKEN_PAUSED
	"DRWA_AUDITOR_APPROVAL_REQUIRED": "auditor_required",          // alias of AUDITOR_REQUIRED
	"DRWA_METADATA_PROTECTED":        "auditor_required",          // alias of AUDITOR_REQUIRED
	"DRWA_HOLDER_NOT_ALLOWED":        "kyc_required",              // alias of KYC_REQUIRED
	"DRWA_RECIPIENT_NOT_ALLOWED":     "kyc_required",              // alias of KYC_REQUIRED
	"DRWA_SENDER_NOT_ALLOWED":        "kyc_required",              // alias of KYC_REQUIRED
	"DRWA_COMPLIANCE_STATE_MISSING":  "compliance_state_missing",  // no canonical equivalent
}

// Denial describes a stable DRWA failure exposed to SDK and client code.
type Denial struct {
	Domain        string
	Identifier    string
	Code          string
	Message       string
	DenialContext string
	TxHash        string
}

func ParseDenial(message string) (*Denial, bool) {
	identifier := denialPattern.FindString(message)
	if identifier == "" {
		return nil, false
	}

	code, ok := knownDenialCodes[identifier]
	if !ok {
		code = strings.ToLower(strings.TrimPrefix(identifier, denialPrefix))
		recordMetric("drwa_unknown_identifier")
	} else {
		recordMetric("drwa_known_identifier")
	}
	recordMetric("drwa_denial_detected")
	recordMetric("drwa_denial_code_" + strings.ToLower(identifier))

	return &Denial{
		Domain:     "drwa",
		Identifier: identifier,
		Code:       code,
		Message:    message,
	}, true
}

func DecodeDenialFromMap(payload map[string]any) (*Denial, bool) {
	if payload == nil {
		return nil, false
	}

	if raw, ok := payload["drwa"].(map[string]any); ok {
		identifier, _ := raw["denialCode"].(string)
		if identifier == "" {
			identifier, _ = raw["error"].(string)
		}
		if identifier != "" {
			denial, _ := ParseDenial(identifier)
			if denial == nil {
				return nil, false
			}
			if message, ok := raw["denialMessage"].(string); ok && message != "" {
				denial.Message = message
			}
			if context, ok := raw["denialContext"].(string); ok {
				denial.DenialContext = context
			}
			if txHash, ok := raw["txHash"].(string); ok {
				denial.TxHash = txHash
			} else if txHash, ok := payload["txHash"].(string); ok {
				denial.TxHash = txHash
			}
			return denial, true
		}
	}

	for _, key := range []string{"returnMessage", "message", "error"} {
		if message, ok := payload[key].(string); ok {
			if denial, found := ParseDenial(message); found {
				if txHash, ok := payload["txHash"].(string); ok {
					denial.TxHash = txHash
				}
				return denial, true
			}
		}
	}

	return nil, false
}

func IsRegulatedFailure(payload map[string]any) bool {
	_, ok := DecodeDenialFromMap(payload)
	return ok
}

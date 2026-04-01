package drwa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDenial(t *testing.T) {
	ResetMetrics()

	denial, ok := ParseDenial("DRWA_KYC_REQUIRED")

	require.True(t, ok)
	require.Equal(t, "drwa", denial.Domain)
	require.Equal(t, "DRWA_KYC_REQUIRED", denial.Identifier)
	require.Equal(t, "kyc_required", denial.Code)
	require.Equal(t, uint64(1), SnapshotMetrics()["drwa_known_identifier"])
}

func TestDecodeDenialFromMap(t *testing.T) {
	t.Parallel()

	denial, ok := DecodeDenialFromMap(map[string]any{
		"txHash": "abc",
		"drwa": map[string]any{
			"denialCode":    "DRWA_GLOBAL_PAUSE",
			"denialMessage": "DRWA_GLOBAL_PAUSE",
			"denialContext": "source",
		},
	})

	require.True(t, ok)
	require.Equal(t, "token_paused", denial.Code)
	require.Equal(t, "source", denial.DenialContext)
	require.Equal(t, "abc", denial.TxHash)
}

func TestParseDenialExtractsIdentifierFromFreeFormMessage(t *testing.T) {
	t.Parallel()

	denial, ok := ParseDenial("execution failed: DRWA_GLOBAL_PAUSE downstream")

	require.True(t, ok)
	require.Equal(t, "DRWA_GLOBAL_PAUSE", denial.Identifier)
	require.Equal(t, "token_paused", denial.Code)
	require.Equal(t, "execution failed: DRWA_GLOBAL_PAUSE downstream", denial.Message)
}

func TestParseDenialMapsProtocolEmittedCodes(t *testing.T) {
	ResetMetrics()

	denial, ok := ParseDenial("execution failed: DRWA_AML_BLOCKED holder blocked")

	require.True(t, ok)
	require.Equal(t, "DRWA_AML_BLOCKED", denial.Identifier)
	require.Equal(t, "aml_blocked", denial.Code)
	require.Equal(t, uint64(1), SnapshotMetrics()["drwa_denial_code_drwa_aml_blocked"])
}

func TestParseDenialRecordsUnknownIdentifierFallback(t *testing.T) {
	ResetMetrics()

	denial, ok := ParseDenial("execution failed: DRWA_CUSTOM_POLICY_BLOCK downstream")

	require.True(t, ok)
	require.Equal(t, "custom_policy_block", denial.Code)
	require.Equal(t, uint64(1), SnapshotMetrics()["drwa_unknown_identifier"])
}

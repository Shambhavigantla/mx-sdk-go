package drwa

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetPolicySummary(t *testing.T) {
	t.Parallel()

	summary, ok := GetPolicySummary(map[string]any{
		"drwa": map[string]any{
			"regulated":          true,
			"policyId":           "policy-1",
			"tokenPolicyVersion": 7,
			"globalPause":        false,
			"strictAuditorMode":  true,
		},
	})

	require.True(t, ok)
	require.True(t, summary.Regulated)
	require.Equal(t, "policy-1", summary.PolicyID)
	require.Equal(t, uint32(7), summary.TokenPolicyVersion)
	require.True(t, summary.StrictAuditorMode)
}

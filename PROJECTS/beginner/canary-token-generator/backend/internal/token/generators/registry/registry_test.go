// ©AngelaMos | 2026
// registry_test.go

package registry_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/registry"
)

const testBaseURL = "https://canary.example.com"

func TestBuild_RegistersWebbug(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg[token.TypeWebbug]
	require.True(t, ok, "expected webbug generator registered")
	require.NotNil(t, g)
	require.Equal(t, token.TypeWebbug, g.Type())
}

func TestBuild_RegistersSlowRedirect(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg[token.TypeSlowRedirect]
	require.True(t, ok, "expected slowredirect generator registered")
	require.NotNil(t, g)
	require.Equal(t, token.TypeSlowRedirect, g.Type())
}

func TestBuild_RegistersDocx(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg[token.TypeDocx]
	require.True(t, ok, "expected docx generator registered")
	require.NotNil(t, g)
	require.Equal(t, token.TypeDocx, g.Type())
}

func TestBuild_RegistersPDF(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg[token.TypePDF]
	require.True(t, ok, "expected pdf generator registered")
	require.NotNil(t, g)
	require.Equal(t, token.TypePDF, g.Type())
}

func TestBuild_RegistersKubeconfig(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg[token.TypeKubeconfig]
	require.True(t, ok, "expected kubeconfig generator registered")
	require.NotNil(t, g)
	require.Equal(t, token.TypeKubeconfig, g.Type())
}

func TestBuild_UnknownTypeReturnsZeroValue(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	g, ok := reg["nonexistent-type"]
	require.False(t, ok, "unknown type must not be present")
	require.Nil(t, g, "map zero value for missing key must be nil interface")
}

func TestBuild_PendingTypesNotYetRegistered(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	pending := []token.Type{
		token.TypeEnvfile,
		token.TypeMySQL,
	}
	for _, tt := range pending {
		_, ok := reg[tt]
		require.False(
			t,
			ok,
			"type %q is not yet registered (subsequent phases will add it); registry must not claim it",
			tt,
		)
	}
}

func TestBuild_OnlyExpectedTypesPresentInPhase6(t *testing.T) {
	reg := registry.Build(registry.Config{BaseURL: testBaseURL})
	require.Len(
		t,
		reg,
		5,
		"Phase 6 registers exactly five generators (webbug, slowredirect, docx, pdf, kubeconfig); other phases append",
	)
}

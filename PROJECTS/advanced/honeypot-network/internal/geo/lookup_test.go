/*
©AngelaMos | 2026
lookup_test.go
*/

package geo

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveMissingDatabasesReturnsZeroValue(t *testing.T) {
	l, err := NewLookup("/nonexistent/city.mmdb", "/nonexistent/asn.mmdb")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	info, err := l.Resolve("8.8.8.8")
	require.NoError(t, err)
	assert.Empty(t, info.Country)
	assert.Zero(t, info.ASN)
}

func TestResolvePrivateAndLoopbackShortCircuits(t *testing.T) {
	l, err := NewLookup("/nonexistent/city.mmdb", "/nonexistent/asn.mmdb")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1"} {
		info, err := l.Resolve(ip)
		require.NoError(t, err)
		assert.Equal(t, "", info.Country)
		assert.Equal(t, float64(0), info.Latitude)
	}
}

func TestResolveInvalidIPErrors(t *testing.T) {
	l, err := NewLookup("/nonexistent/city.mmdb", "/nonexistent/asn.mmdb")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	_, err = l.Resolve("not-an-ip")
	assert.Error(t, err)
}

// TestResolveWithRealDatabases only runs if HIVE_TEST_GEOIP_CITY and
// HIVE_TEST_GEOIP_ASN point at real .mmdb files (e.g. downloaded via
// `just geoip-update`). Skipped otherwise so CI doesn't need a
// MaxMind license.
func TestResolveWithRealDatabases(t *testing.T) {
	cityPath := os.Getenv("HIVE_TEST_GEOIP_CITY")
	asnPath := os.Getenv("HIVE_TEST_GEOIP_ASN")
	if cityPath == "" || asnPath == "" {
		t.Skip("set HIVE_TEST_GEOIP_CITY and HIVE_TEST_GEOIP_ASN to run")
	}

	l, err := NewLookup(cityPath, asnPath)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	// Google DNS — stable, well-known geolocation (Mountain View / AS15169)
	info, err := l.Resolve("8.8.8.8")
	require.NoError(t, err)
	assert.Equal(t, "US", info.CountryCode)
	assert.Equal(t, 15169, info.ASN)
	assert.NotEmpty(t, info.Org)
	assert.NotZero(t, info.Latitude)
}

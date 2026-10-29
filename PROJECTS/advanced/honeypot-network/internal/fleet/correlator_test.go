/*
©AngelaMos | 2026
correlator_test.go
*/

package fleet

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCorrelatorFlagsSecondSensor(t *testing.T) {
	c := NewCorrelator(10 * time.Minute)
	now := time.Now()

	assert.Nil(t, c.Observe("203.0.113.1", "a", now))
	assert.Nil(t, c.Observe("203.0.113.1", "a", now.Add(time.Second)))

	got := c.Observe("203.0.113.1", "b", now.Add(2*time.Second))
	require.NotNil(t, got)
	assert.Equal(t, []string{"a", "b"}, got.Sensors)

	assert.Nil(t, c.Observe("203.0.113.1", "b", now.Add(3*time.Second)))
	assert.Len(t, c.Recent(10), 1)
}

func TestCorrelatorWindowExpiry(t *testing.T) {
	c := NewCorrelator(10 * time.Minute)
	now := time.Now()

	c.Observe("203.0.113.1", "a", now)
	assert.Nil(t, c.Observe("203.0.113.1", "b", now.Add(11*time.Minute)))
}

func TestCorrelatorReportsThirdSensor(t *testing.T) {
	c := NewCorrelator(time.Hour)
	now := time.Now()

	c.Observe("203.0.113.1", "a", now)
	c.Observe("203.0.113.1", "b", now)
	got := c.Observe("203.0.113.1", "c", now)
	require.NotNil(t, got)
	assert.Len(t, got.Sensors, 3)
}
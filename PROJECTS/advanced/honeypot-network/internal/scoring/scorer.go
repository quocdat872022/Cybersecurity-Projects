/*
©AngelaMos | 2026
scorer.go

# Session threat scoring weights and single-event classification

Assigns point values to attacker actions observed during a honeypot
session. Scores accumulate on the session record and are capped at
100 to prevent runaway values from long brute-force sessions.
Multi-event contributions (MITRE technique diversity, session
duration) are awarded by the caller since they depend on
session-level state rather than a single event.
*/
package scoring

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	MaxScore = 100

	WeightAuthAttempt      = 5
	WeightDiscoveryCommand = 10
	WeightToolTransfer     = 20
	WeightPersistence      = 25
	WeightMITRETechnique   = 15
	WeightLongSession      = 10

	LongSessionThreshold = 30 * time.Second
)

// ScoreEvent returns the point value contributed by a single event.
// Authentication attempts and classified commands score immediately;
// everything else returns 0.
func ScoreEvent(ev *types.Event) int {
	switch ev.EventType {
	case types.EventLoginSuccess, types.EventLoginFailed:
		return WeightAuthAttempt

	case types.EventCommand:
		return scoreCommand(extractCommand(ev.ServiceData))

	case types.EventFileUpload:
		return WeightToolTransfer

	default:
		return 0
	}
}

func scoreCommand(cmd string) int {
	if cmd == "" {
		return 0
	}

	upper := strings.ToUpper(cmd)
	score := 0

	if isDiscoveryCommand(upper) {
		score += WeightDiscoveryCommand
	}
	if isToolTransfer(upper) {
		score += WeightToolTransfer
	}
	if isPersistence(upper) {
		score += WeightPersistence
	}

	return score
}

func isDiscoveryCommand(cmd string) bool {
	patterns := []string{
		"UNAME", "HOSTNAME", "WHOAMI", "ID",
		"CAT /ETC/PASSWD", "CAT /ETC/SHADOW",
		"CAT /ETC/OS-RELEASE", "CAT /PROC/VERSION",
		"CAT /PROC/CPUINFO", "CAT /PROC/MEMINFO",
		"LSBLK", "LSCPU", "DMIDECODE",
	}
	for _, p := range patterns {
		if strings.Contains(cmd, p) {
			return true
		}
	}
	return false
}

func isToolTransfer(cmd string) bool {
	patterns := []string{
		"WGET ", "CURL ", "FETCH ",
		"TFTP ", "SCP ", "SFTP ",
		"FTP ", "LWPDOWNLOAD",
	}
	for _, p := range patterns {
		if strings.Contains(cmd, p) {
			return true
		}
	}
	return false
}

func isPersistence(cmd string) bool {
	patterns := []string{
		"CRONTAB", "/ETC/CRON",
		"/VAR/SPOOL/CRON", "SYSTEMCTL",
		"/ETC/SYSTEMD", "/ETC/INIT.D",
	}
	for _, p := range patterns {
		if strings.Contains(cmd, p) {
			return true
		}
	}
	return false
}

func extractCommand(data json.RawMessage) string {
	if len(data) == 0 {
		return ""
	}
	var parsed map[string]interface{}
	if json.Unmarshal(data, &parsed) != nil {
		return ""
	}
	if cmd, ok := parsed["command"].(string); ok {
		return cmd
	}
	if q, ok := parsed["query"].(string); ok {
		return q
	}
	return ""
}

// Cap clamps a score to the valid [0, MaxScore] range.
func Cap(score int) int {
	if score > MaxScore {
		return MaxScore
	}
	if score < 0 {
		return 0
	}
	return score
}

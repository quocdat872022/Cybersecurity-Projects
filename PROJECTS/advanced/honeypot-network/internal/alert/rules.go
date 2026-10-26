/*
©AngelaMos | 2026
rules.go

Alert rule definitions for real-time webhook alerting

Each rule inspects a single event together with its MITRE detections
and a snapshot of the owning session, and returns zero or more
findings. Findings are deduplicated and delivered by the Engine.
*/

package alert

import (
	"fmt"
	"strings"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	RuleBruteForce   = "brute_force"
	RuleToolTransfer = "tool_transfer"
	RuleHighThreat   = "high_threat"
	RuleNewTechnique = "new_technique"
)

const (
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

const (
	techBruteForce   = "T1110"
	techToolTransfer = "T1105"
	tagSMTPMessage   = "smtp-message"
)

// Finding is a single rule match. Key scopes deduplication: the
// engine suppresses repeat findings with the same rule and key until
// the cooldown elapses.
type Finding struct {
	Rule     string
	Severity string
	Summary  string
	Key      string
}

type EvalContext struct {
	Event         *types.Event
	Detections    []*types.MITREDetection
	NewDetections []*types.MITREDetection
	Session       *types.Session
	MinScore      int
}

type Rule interface {
	Name() string
	Evaluate(c *EvalContext) []Finding
}

type funcRule struct {
	name string
	fn   func(c *EvalContext) []Finding
}

func (r funcRule) Name() string { return r.name }

func (r funcRule) Evaluate(c *EvalContext) []Finding {
	return r.fn(c)
}

func AllRules() []Rule {
	return []Rule{
		funcRule{RuleBruteForce, evalBruteForce},
		funcRule{RuleToolTransfer, evalToolTransfer},
		funcRule{RuleHighThreat, evalHighThreat},
		funcRule{RuleNewTechnique, evalNewTechnique},
	}
}

func RuleNames() []string {
	rules := AllRules()
	names := make([]string, len(rules))
	for i, r := range rules {
		names[i] = r.Name()
	}
	return names
}

// SelectRules resolves configured rule names. An empty list enables
// every rule; an unknown name is a configuration error.
func SelectRules(names []string) ([]Rule, error) {
	all := AllRules()
	if len(names) == 0 {
		return all, nil
	}

	byName := make(map[string]Rule, len(all))
	for _, r := range all {
		byName[r.Name()] = r
	}

	var selected []Rule
	seen := make(map[string]bool)
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || seen[n] {
			continue
		}
		r, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf(
				"unknown alert rule %q (valid: %s)",
				n, strings.Join(RuleNames(), ", "),
			)
		}
		seen[n] = true
		selected = append(selected, r)
	}

	if len(selected) == 0 {
		return all, nil
	}
	return selected, nil
}

func hasTechnique(
	dets []*types.MITREDetection, id string,
) bool {
	for _, d := range dets {
		if d.TechniqueID == id {
			return true
		}
	}
	return false
}

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

func evalBruteForce(c *EvalContext) []Finding {
	if !hasTechnique(c.Detections, techBruteForce) {
		return nil
	}
	ev := c.Event
	return []Finding{{
		Rule:     RuleBruteForce,
		Severity: SeverityHigh,
		Key:      ev.SourceIP,
		Summary: fmt.Sprintf(
			"Brute force detected from %s against %s",
			ev.SourceIP, ev.ServiceType.Label(),
		),
	}}
}

func evalToolTransfer(c *EvalContext) []Finding {
	ev := c.Event
	if hasTag(ev.Tags, tagSMTPMessage) {
		return nil
	}
	if !hasTechnique(c.Detections, techToolTransfer) {
		return nil
	}
	return []Finding{{
		Rule:     RuleToolTransfer,
		Severity: SeverityHigh,
		Key:      ev.SourceIP,
		Summary: fmt.Sprintf(
			"Tool transfer attempt from %s via %s",
			ev.SourceIP, ev.ServiceType.Label(),
		),
	}}
}

func evalHighThreat(c *EvalContext) []Finding {
	if c.MinScore <= 0 || c.Session == nil ||
		c.Session.ThreatScore < c.MinScore {
		return nil
	}
	return []Finding{{
		Rule:     RuleHighThreat,
		Severity: SeverityCritical,
		Key:      c.Session.ID,
		Summary: fmt.Sprintf(
			"High-threat session from %s (score %d)",
			c.Session.SourceIP, c.Session.ThreatScore,
		),
	}}
}

func evalNewTechnique(c *EvalContext) []Finding {
	findings := make([]Finding, 0, len(c.NewDetections))
	for _, d := range c.NewDetections {
		findings = append(findings, Finding{
			Rule:     RuleNewTechnique,
			Severity: SeverityMedium,
			Key:      d.TechniqueID,
			Summary: fmt.Sprintf(
				"New MITRE technique observed: %s (%s) from %s",
				d.TechniqueID, d.Tactic, d.SourceIP,
			),
		})
	}
	return findings
}
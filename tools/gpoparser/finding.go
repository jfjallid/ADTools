package main

import (
	"fmt"
	"sort"
	"strings"
)

// Severity follows Group3r's four-tier triage (cleaner than Grouper2's 1-10):
// Info (noteworthy), Low (weakens posture), High (exploitable by the assessed
// user), Critical (credentials in the open or GPO takeover).
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "critical"
	case SevHigh:
		return "high"
	case SevLow:
		return "low"
	default:
		return "info"
	}
}

// label is the bracketed tag used in text output, e.g. "[HIGH]".
func (s Severity) label() string {
	return "[" + strings.ToUpper(s.String()) + "]"
}

// MarshalJSON renders the severity as its lower-case name.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// parseSeverity maps a name (info/low/high/critical) to a Severity.
func parseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "informational", "":
		return SevInfo, nil
	case "low", "yellow":
		return SevLow, nil
	case "high", "red":
		return SevHigh, nil
	case "critical", "crit", "black":
		return SevCritical, nil
	default:
		return SevInfo, fmt.Errorf("unknown severity %q (want info|low|high|critical)", s)
	}
}

// WriteSurface names the object whose ACL/writability a finding concerns.
type WriteSurface string

const (
	surfaceGPOObject WriteSurface = "gpo-object"      // the groupPolicyContainer in AD
	surfaceSysvol    WriteSurface = "sysvol-file"     // a parsed file under SYSVOL
	surfacePath      WriteSurface = "referenced-path" // a UNC/local path a setting points at
)

// WriteAssessment records that the assessed user can modify some surface. It is
// populated by the live ACL checks (Phase 4); offline findings leave it nil.
type WriteAssessment struct {
	Surface WriteSurface `json:"surface"`
	Path    string       `json:"path,omitempty"`
	Trustee Principal    `json:"trustee"`
	Rights  []string     `json:"rights,omitempty"`
	Existed bool         `json:"existed"` // false => parent was writable (attacker can create)
}

// Finding is one assessed misconfiguration in a GPO.
type Finding struct {
	GPO        string           `json:"gpo"` // GUID
	GPOName    string           `json:"gpo_name"`
	Scope      string           `json:"scope"`    // "Computer" | "User"
	Category   string           `json:"category"` // stable id, e.g. "user-rights"
	Severity   Severity         `json:"severity"`
	Reason     string           `json:"reason"`
	Detail     string           `json:"detail,omitempty"`
	Reference  string           `json:"reference,omitempty"`
	Principals []Principal      `json:"principals,omitempty"`
	Writable   *WriteAssessment `json:"writable,omitempty"`
	// AffectedComputers is copied from the GPO so each finding carries its blast
	// radius — something Group3r cannot easily produce.
	AffectedComputers []string `json:"affected_computers,omitempty"`
}

// assessCtx carries cross-cutting helpers for analysers. resolver is nil in the
// offline path (Phase 1); the live ACL checks (Phase 4) populate it.
type assessCtx struct {
	resolver *sidResolver
}

// analyserFunc inspects one configuration scope of a GPO and returns findings.
// g and ctx are passed for forward-compatibility with the writability checks;
// the Phase 1 analysers use only cs and scope.
type analyserFunc func(g *GPO, scope string, cs *ConfigSettings, ctx *assessCtx) []Finding

type analyser struct {
	id string
	fn analyserFunc
}

var analysers []analyser

// registerAnalyser adds an analyser to the assessment pipeline. Called from
// init() functions in the analyser files.
func registerAnalyser(id string, fn analyserFunc) {
	analysers = append(analysers, analyser{id: id, fn: fn})
}

// runAssessment runs every registered analyser over the Computer and User scope
// of each GPO, attaches GPO identity and blast radius, drops findings below min,
// and returns them sorted most-severe first.
func runAssessment(gpos []*GPO, ctx *assessCtx, min Severity) []Finding {
	var out []Finding
	for _, g := range gpos {
		scopes := []struct {
			name string
			cs   *ConfigSettings
		}{
			{"Computer", &g.Computer},
			{"User", &g.User},
		}
		for _, sc := range scopes {
			if sc.cs.empty() {
				continue
			}
			for _, a := range analysers {
				for _, f := range a.fn(g, sc.name, sc.cs, ctx) {
					f.GPO = g.GUID
					f.GPOName = g.Name
					f.Scope = sc.name
					if len(f.AffectedComputers) == 0 {
						f.AffectedComputers = g.AffectedComputers
					}
					if f.Severity >= min {
						out = append(out, f)
					}
				}
			}
		}
	}
	sortFindings(out)
	return out
}

// sortFindings orders findings most-severe first, then by GPO name and category.
func sortFindings(out []Finding) {
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if out[i].GPOName != out[j].GPOName {
			return out[i].GPOName < out[j].GPOName
		}
		return out[i].Category < out[j].Category
	})
}

// joinPrincipals renders a principal list for the Detail field.
func joinPrincipals(ps []Principal) string {
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ", ")
}

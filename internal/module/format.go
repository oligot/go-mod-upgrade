package module

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

// The values accepted by the --format flag.
const (
	// FormatText is the aligned listing meant to be read.
	FormatText = "text"
	// FormatPolicy is the module map of a policy file, ready to be passed
	// back as a policy.
	FormatPolicy = "policy"
	// FormatJSON is a report of what was found, for other tooling.
	FormatJSON = "json"
)

// DefaultFormat is the listing the tool has always printed.
const DefaultFormat = FormatText

// FormatNames lists the accepted values, for help text and error messages.
func FormatNames() []string {
	return []string{FormatText, FormatPolicy, FormatJSON}
}

// ValidFormat reports whether a name is one the tool writes.
func ValidFormat(name string) error {
	if slices.Contains(FormatNames(), name) {
		return nil
	}
	return fmt.Errorf("unknown format %q, expected one of: %s",
		name, strings.Join(FormatNames(), ", "))
}

// WritePolicy writes the modules as the module map of a policy file.
//
// Each entry defers to go.mod rather than naming a version, so the generated
// file states which modules are permitted and leaves the versions to the
// document that already records them. Regenerating it produces the same bytes
// unless the set of modules changed, which keeps it reviewable in a diff.
func WritePolicy(w io.Writer, modules []Module) error {
	type entry struct {
		Allow string `json:"allow"`
	}
	out := struct {
		Modules map[string]entry `json:"modules"`
	}{Modules: make(map[string]entry, len(modules))}

	for _, mod := range modules {
		out.Modules[mod.Name] = entry{Allow: "go.mod"}
	}
	return write(w, out)
}

// reported is one module as the JSON report describes it.
type reported struct {
	Version  string   `json:"version"`
	Update   string   `json:"update,omitempty"`
	Indirect bool     `json:"indirect,omitempty"`
	Vulns    []string `json:"vulns,omitempty"`
	// Reachable counts the advisories covering code this project reaches,
	// which is what distinguishes one to act on from one to note.
	Reachable int `json:"reachable,omitempty"`
	// Deprecated and Retracted carry what the author said, and Archived what a
	// policy asserted. Each holds the message rather than a flag, since the
	// reason is what a reader has to act on.
	Deprecated string   `json:"deprecated,omitempty"`
	Retracted  []string `json:"retracted,omitempty"`
	Archived   string   `json:"archived,omitempty"`
	// FixedBy names the upgrades that would resolve this module's advisories
	// without it being upgraded itself.
	FixedBy []string `json:"fixed_by,omitempty"`
	// Fixes names the modules whose advisories this upgrade would resolve.
	Fixes      []string `json:"fixes,omitempty"`
	RequiredBy []string `json:"required_by,omitempty"`
}

// WriteJSON writes a report of the modules for other tooling to read.
func WriteJSON(w io.Writer, modules []Module) error {
	out := struct {
		Modules map[string]reported `json:"modules"`
	}{Modules: make(map[string]reported, len(modules))}

	for _, mod := range modules {
		r := reported{
			Version:    mod.From.Original(),
			Indirect:   mod.Indirect,
			Vulns:      mod.Vulns,
			Reachable:  mod.Reachable,
			Deprecated: mod.Deprecated,
			Retracted:  mod.Retracted,
			Archived:   mod.Archived,
			FixedBy:    mod.FixedBy,
			Fixes:      mod.Fixes,
			RequiredBy: mod.RequiredBy,
		}
		if !mod.From.Equal(mod.To) {
			r.Update = mod.To.Original()
		}
		out.Modules[mod.Name] = r
	}
	return write(w, out)
}

// write emits indented JSON with a trailing newline, so the output is a
// well-formed file rather than a fragment.
func write(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("error writing output: %w", err)
	}
	return nil
}

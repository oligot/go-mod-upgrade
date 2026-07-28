package module

import (
	"fmt"
	"slices"
	"strings"
)

// The keys accepted by the --show flag. They name the same properties as the
// --sort keys, so the two flags read alike: --sort orders a listing and --show
// decides what is in it.
const (
	// ShowCVE keeps the modules carrying an advisory.
	ShowCVE = "cve"
	// ShowDelta keeps the modules with a newer version available.
	ShowDelta = "delta"
	// ShowDirect and ShowIndirect keep the modules by how they are required.
	ShowDirect   = "direct"
	ShowIndirect = "indirect"
	// ShowDisowned keeps the modules given up on, whether by their author or by
	// a reviewer. It covers all three, since what a reader usually wants is
	// every module that has been abandoned rather than one flavour of it.
	ShowDisowned = "disowned"
	// ShowAll keeps everything, which is what a policy is generated from.
	ShowAll = "all"
)

// DefaultShow keeps the modules with an upgrade available, which is what the
// tool has always listed.
const DefaultShow = "+" + ShowDelta

// filters maps each key to what it keeps.
var filters = map[string]func(Module) bool{
	ShowCVE:      func(m Module) bool { return len(m.Vulns) > 0 },
	ShowDelta:    func(m Module) bool { return !m.From.Equal(m.To) },
	ShowDirect:   func(m Module) bool { return !m.Indirect },
	ShowIndirect: func(m Module) bool { return m.Indirect },
	ShowDisowned: func(m Module) bool { return m.Disowned() },
	ShowAll:      func(Module) bool { return true },
}

// ShowKeys lists the accepted keys, for help text and error messages.
func ShowKeys() []string {
	return []string{ShowCVE, ShowDelta, ShowDirect, ShowIndirect, ShowDisowned, ShowAll}
}

// Show decides which modules a listing contains.
type Show struct {
	// Keys names the chain as given, for reporting.
	Keys []string

	keep []func(Module) bool
	drop []func(Module) bool
}

// Keep reports whether a module belongs in the listing.
//
// A module is kept when any of the requested properties holds, so
// "+cve,+delta" means an advisory or an available upgrade. A negated key
// excludes regardless, so "+all,-indirect" is everything a project requires
// directly.
func (s Show) Keep(mod Module) bool {
	// A module withheld by --ignore is never listed, whatever was asked for.
	// It is still checked against a policy, which happens before this.
	if mod.Ignored {
		return false
	}
	for _, drop := range s.drop {
		if drop(mod) {
			return false
		}
	}
	if len(s.keep) == 0 {
		return true
	}
	for _, keep := range s.keep {
		if keep(mod) {
			return true
		}
	}
	return false
}

// ParseShow reads a comma-separated chain of keys, each optionally signed. A
// key prefixed with "-" excludes rather than includes.
func ParseShow(spec string) (Show, error) {
	if strings.TrimSpace(spec) == "" {
		spec = DefaultShow
	}

	var s Show
	for _, field := range strings.Split(spec, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		exclude := false
		switch field[0] {
		case '-':
			exclude = true
			field = field[1:]
		case '+':
			field = field[1:]
		}
		key := strings.ToLower(field)
		filter, ok := filters[key]
		if !ok {
			return Show{}, &UnknownShowError{Key: key}
		}
		s.Keys = append(s.Keys, key)
		if exclude {
			s.drop = append(s.drop, filter)
		} else {
			s.keep = append(s.keep, filter)
		}
	}
	return s, nil
}

// UnknownShowError reports a --show key with no filter.
type UnknownShowError struct {
	Key string
}

func (e *UnknownShowError) Error() string {
	return fmt.Sprintf("unknown show key %q, expected one of: %s",
		e.Key, strings.Join(ShowKeys(), ", "))
}

// Filter returns the modules a listing should contain, in the order given.
func Filter(modules []Module, show Show) []Module {
	kept := make([]Module, 0, len(modules))
	for _, mod := range modules {
		if show.Keep(mod) {
			kept = append(kept, mod)
		}
	}
	return slices.Clip(kept)
}

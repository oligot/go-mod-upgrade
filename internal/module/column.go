package module

import (
	"fmt"
	"slices"
	"strings"
)

// The columns a listing can hold. Each names one thing about a module, so what a
// row shows is decided by which columns are asked for rather than by which flags
// happened to be given.
const (
	// ColumnName is the module path.
	ColumnName = "name"
	// ColumnLabel holds the letters saying why a row is where it is: how the
	// module is required, what its author said about it, and whether an upgrade
	// elsewhere already resolves it.
	ColumnLabel = "label"
	// ColumnCVE lists the advisories affecting the current version.
	ColumnCVE = "cve"
	// ColumnFrom and ColumnTo are the current version and the one available.
	ColumnFrom = "from"
	ColumnTo   = "to"
	// ColumnHint says what taking this upgrade would resolve elsewhere, or what
	// would resolve this module without upgrading it.
	ColumnHint = "hint"
	// ColumnRequiredBy names what pulls the module in.
	ColumnRequiredBy = "required-by"
	// ColumnTags names the build configurations that reach the module, shown only
	// when they differ between modules.
	ColumnTags = "tags"
	// ColumnCooldown says how long the version on offer has been out while it is
	// still settling, and the date it landed once it has. One column answering
	// whichever question is worth asking.
	ColumnCooldown = "cooldown"
	// ColumnAge and ColumnReleaseDate answer those questions unconditionally, for a
	// reader who wants one of them whatever the cooldown makes of the module.
	ColumnAge         = "age"
	ColumnReleaseDate = "release-date"
)

// columnOrder is every column in the order a row renders them. A set is always
// displayed in this order rather than the order it was written, so two callers
// asking for the same columns get the same layout.
var columnOrder = []string{
	ColumnName, ColumnLabel, ColumnCVE, ColumnFrom, ColumnTo,
	ColumnHint, ColumnCooldown, ColumnAge, ColumnReleaseDate,
	ColumnTags, ColumnRequiredBy,
}

// ColumnNames lists the accepted column keys, for help text and error messages.
func ColumnNames() []string { return slices.Clone(columnOrder) }

// headings are the labels a header row shows for each column.
var headings = map[string]string{
	ColumnName:        "MODULE",
	ColumnLabel:       "LABELS",
	ColumnCVE:         "ADVISORY",
	ColumnFrom:        "FROM",
	ColumnTo:          "TO",
	ColumnHint:        "RESOLVES",
	ColumnCooldown:    "COOLDOWN",
	ColumnAge:         "AGE",
	ColumnReleaseDate: "RELEASED",
	ColumnTags:        "TAGS",
	ColumnRequiredBy:  "REQUIRED BY",
}

// Heading returns the header label for a column.
func Heading(column string) string { return headings[column] }

// Columns is the set of columns a listing shows, and the order they appear in.
type Columns struct {
	// Spec is the chain as given, for reporting.
	Spec string

	want map[string]bool
}

// Has reports whether a column belongs in the listing.
func (c Columns) Has(column string) bool { return c.want[column] }

// Ordered returns the columns to render, in the order a row shows them.
func (c Columns) Ordered() []string {
	var out []string
	for _, column := range columnOrder {
		if c.want[column] {
			out = append(out, column)
		}
	}
	return out
}

// DefaultColumns is what a listing shows when -k is not given: the module, why
// it is listed, and the step between its versions.
//
// The advisory, hint and required-by columns are added by the flags that gather
// what fills them, since a column nothing can fill is only noise.
func DefaultColumns() []string {
	return []string{ColumnName, ColumnLabel, ColumnFrom, ColumnTo}
}

// ParseColumns reads a comma-separated chain of column keys, each optionally
// signed, and returns the set to show.
//
// base is what the flags implied. An unsigned chain replaces it outright, so a
// caller naming exact columns gets exactly those; a chain of signed keys adjusts
// it, so "+required-by" means the usual plus one more. Mixing the two is refused
// rather than guessed at, since "name,+hint" could mean either.
func ParseColumns(spec string, base []string) (Columns, error) {
	c := Columns{Spec: spec, want: map[string]bool{}}
	if strings.TrimSpace(spec) == "" {
		for _, column := range base {
			c.want[column] = true
		}
		return c, nil
	}

	type change struct {
		column string
		add    bool
	}
	var (
		named   []string
		changes []change
	)
	for _, field := range strings.Split(spec, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		signed, add := false, true
		switch field[0] {
		case '-':
			signed, add = true, false
			field = field[1:]
		case '+':
			signed = true
			field = field[1:]
		}

		key := strings.ToLower(strings.TrimSpace(field))
		if !slices.Contains(columnOrder, key) {
			return Columns{}, &UnknownColumnError{Key: key}
		}
		if signed {
			changes = append(changes, change{key, add})
		} else {
			named = append(named, key)
		}
	}

	if len(named) > 0 && len(changes) > 0 {
		return Columns{}, fmt.Errorf(
			"columns %q mixes naming a set with adjusting one; write either a plain list or only signed keys", spec)
	}

	if len(named) > 0 {
		for _, column := range named {
			c.want[column] = true
		}
		return c, nil
	}
	for _, column := range base {
		c.want[column] = true
	}
	for _, ch := range changes {
		c.want[ch.column] = ch.add
	}
	return c, nil
}

// UnknownColumnError reports a -k key naming no column.
type UnknownColumnError struct {
	Key string
}

func (e *UnknownColumnError) Error() string {
	return fmt.Sprintf("unknown column %q, expected one of: %s",
		e.Key, strings.Join(ColumnNames(), ", "))
}

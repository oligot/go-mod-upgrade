package module

import (
	"slices"
	"strings"
	"testing"
)

// TestParseColumnsDefault checks that an empty spec means whatever the flags
// implied, so a caller that names nothing gets the usual listing.
func TestParseColumnsDefault(t *testing.T) {
	base := []string{ColumnName, ColumnFrom, ColumnTo}
	c, err := ParseColumns("", base)
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	if got := c.Ordered(); !slices.Equal(got, base) {
		t.Errorf("got %v, want %v", got, base)
	}
}

// TestParseColumnsReplaces checks that an unsigned chain names the set outright,
// ignoring what the flags implied.
func TestParseColumnsReplaces(t *testing.T) {
	base := []string{ColumnName, ColumnFrom, ColumnTo, ColumnRequiredBy}
	c, err := ParseColumns("name,cve", base)
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	want := []string{ColumnName, ColumnCVE}
	if got := c.Ordered(); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v: a plain list replaces the default", got, want)
	}
}

// TestParseColumnsAdjusts checks that signed keys change the implied set rather
// than replacing it, which is what makes "the usual plus one" expressible.
func TestParseColumnsAdjusts(t *testing.T) {
	base := []string{ColumnName, ColumnFrom, ColumnTo}
	cases := []struct {
		spec string
		want []string
	}{
		{"+label", []string{ColumnName, ColumnLabel, ColumnFrom, ColumnTo}},
		{"-to", []string{ColumnName, ColumnFrom}},
		{"+cve,-from", []string{ColumnName, ColumnCVE, ColumnTo}},
		// Removing something absent is not an error: the result is what was asked
		// for either way.
		{"-required-by", base},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			got, err := ParseColumns(c.spec, base)
			if err != nil {
				t.Fatalf("ParseColumns(%q): %v", c.spec, err)
			}
			if ordered := got.Ordered(); !slices.Equal(ordered, c.want) {
				t.Errorf("got %v, want %v", ordered, c.want)
			}
		})
	}
}

// TestParseColumnsOrderIsFixed checks that a set renders in one order whatever
// order it was written, so two callers asking for the same columns agree.
func TestParseColumnsOrderIsFixed(t *testing.T) {
	first, err := ParseColumns("to,name,cve", nil)
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	second, err := ParseColumns("cve,to,name", nil)
	if err != nil {
		t.Fatalf("ParseColumns: %v", err)
	}
	if !slices.Equal(first.Ordered(), second.Ordered()) {
		t.Errorf("%v and %v differ, want one order whatever the spec", first.Ordered(), second.Ordered())
	}
	want := []string{ColumnName, ColumnCVE, ColumnTo}
	if got := first.Ordered(); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestParseColumnsRejectsMixedForms checks that naming a set and adjusting one in
// the same spec is refused.
//
// "name,+hint" could mean "exactly those two" or "just name, plus the usual
// hint", and guessing either way would surprise half the callers.
func TestParseColumnsRejectsMixedForms(t *testing.T) {
	_, err := ParseColumns("name,+hint", []string{ColumnName, ColumnFrom})
	if err == nil {
		t.Fatal("expected an error for a spec mixing a list with signed keys")
	}
	if !strings.Contains(err.Error(), "mixes") {
		t.Errorf("error %q does not explain the problem", err)
	}
}

func TestParseColumnsUnknownKey(t *testing.T) {
	_, err := ParseColumns("+bogus", nil)
	if err == nil {
		t.Fatal("expected an error for an unknown column")
	}
	// The message has to list what is accepted, since the keys are not guessable.
	for _, key := range ColumnNames() {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q does not mention %q", err, key)
		}
	}
}

// TestHeadingForEveryColumn checks that no column can be shown without a label
// above it, which would leave a header row with a gap.
func TestHeadingForEveryColumn(t *testing.T) {
	for _, column := range ColumnNames() {
		if Heading(column) == "" {
			t.Errorf("column %q has no heading", column)
		}
	}
}

// TestDefaultColumnsDateWhatIsOffered checks that a listing says when the version on
// offer was published and how much longer it has to wait, without being asked.
//
// How old a release is decides whether it is recommended, so it belongs beside the
// version rather than behind a flag: a reader who has to ask for it does not know to
// ask. Two columns because they answer different questions -- RELEASED when it landed,
// COOLDOWN how much longer -- and a single column that switched between them named a
// period while reporting a date, which is what made it unreadable. Each renders empty
// when it has nothing to say, which measure then drops.
func TestDefaultColumnsDateWhatIsOffered(t *testing.T) {
	got := DefaultColumns()
	for _, want := range []string{ColumnReleaseDate, ColumnCooldown} {
		if !slices.Contains(got, want) {
			t.Errorf("DefaultColumns() = %v, want %q", got, want)
		}
	}
	// After the versions they qualify, since both are about the one on offer.
	if slices.Index(got, ColumnReleaseDate) < slices.Index(got, ColumnTo) {
		t.Errorf("DefaultColumns() = %v, want the date after the version it dates", got)
	}
	// The date before the wait: when it landed, then what follows from that.
	if slices.Index(got, ColumnCooldown) < slices.Index(got, ColumnReleaseDate) {
		t.Errorf("DefaultColumns() = %v, want the wait after the date", got)
	}
	// An age stays opt-in: it is the same fact RELEASED carries, said relatively, so
	// showing both by default would be one column too many.
	if slices.Contains(got, ColumnAge) {
		t.Errorf("DefaultColumns() = %v, want %q left to -k", got, ColumnAge)
	}
}

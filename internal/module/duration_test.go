package module

import (
	"fmt"
	"testing"
	"time"
)

// TestParseDuration checks the units a person writes when naming a cooldown.
//
// Go's own parser stops at hours, so "7d" is an error to it -- yet a week is the
// natural way to say how long a release should settle. The units above an hour are
// added, and a bare number is read as days, since that is the scale the periods
// are talked about in.
func TestParseDuration(t *testing.T) {
	day := 24 * time.Hour
	for _, tc := range []struct {
		text string
		want time.Duration
	}{
		{"7d", 7 * day},
		{"1d", day},
		{"2w", 14 * day},
		{"3mo", 90 * day},
		{"1q", 90 * day},
		{"24h", day},
		{"90m", 90 * time.Minute},
		{"36h", 36 * time.Hour},
		// A bare number is days, so --cooldown=7 and --cooldown=7d agree.
		{"7", 7 * day},
		{"0", 0},
		// Compound values, as Go's own parser accepts.
		{"1d12h", 36 * time.Hour},
		{"1w2d", 9 * day},
		// Whitespace is a typo rather than a meaning.
		{" 7d ", 7 * day},
	} {
		t.Run(tc.text, func(t *testing.T) {
			got, err := ParseDuration(tc.text)
			if err != nil {
				t.Fatalf("ParseDuration(%q): %v", tc.text, err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParseDurationRejects checks that a value which cannot be read is reported
// rather than quietly taken as zero, which would disable the cooldown.
func TestParseDurationRejects(t *testing.T) {
	for _, text := range []string{
		"",
		"7x",
		"d",
		"seven",
		// Negative periods would make everything eligible, which is not what
		// anyone means by a cooldown.
		"-1d",
		"-7",
	} {
		t.Run(text, func(t *testing.T) {
			if got, err := ParseDuration(text); err == nil {
				t.Errorf("ParseDuration(%q) = %v, want an error", text, got)
			}
		})
	}
}

// TestParseDurationMonthsBeforeMinutes pins the one ambiguity in the units: "mo"
// has to be matched before "m", or a month is read as a minute and the value is
// wrong by a factor of forty thousand.
func TestParseDurationMonthsBeforeMinutes(t *testing.T) {
	month, err := ParseDuration("1mo")
	if err != nil {
		t.Fatalf("ParseDuration: %v", err)
	}
	minute, err := ParseDuration("1m")
	if err != nil {
		t.Fatalf("ParseDuration: %v", err)
	}
	if month == minute {
		t.Fatalf("a month and a minute both parsed as %v", month)
	}
	if want := 30 * 24 * time.Hour; month != want {
		t.Errorf("1mo = %v, want %v", month, want)
	}
}

// TestFormatDuration checks that a period is rendered in the largest unit that
// divides it exactly, so a listing says "1w" rather than "168h0m0s".
//
// Largest rather than most familiar: 168h is both a week and seven days, and picking
// one per unit would be a judgement to remember instead of a rule to apply. Below an
// hour Go's own rendering is already what a reader expects.
func TestFormatDuration(t *testing.T) {
	day := 24 * time.Hour
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		// A week divides seven days, so the week wins.
		{7 * day, "1w"},
		{14 * day, "2w"},
		// A quarter divides ninety days and three months alike.
		{90 * day, "1q"},
		{60 * day, "2mo"},
		{day, "1d"},
		{3 * day, "3d"},
		// Nothing above an hour divides these, so Go renders them.
		{36 * time.Hour, "36h0m0s"},
		{90 * time.Minute, "1h30m0s"},
		{0, "0s"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			if got := FormatDuration(tc.d); got != tc.want {
				t.Errorf("FormatDuration(%v) = %q, want %q", tc.d, got, tc.want)
			}
		})
	}
}

// TestDurationRoundTrips checks that what is rendered can be read back, since the
// rendered form is what a listing shows and a reader may paste it into a flag.
func TestDurationRoundTrips(t *testing.T) {
	day := 24 * time.Hour
	for _, d := range []time.Duration{
		7 * day, 14 * day, 30 * day, 90 * day, 36 * time.Hour, 90 * time.Minute,
	} {
		t.Run(fmt.Sprint(d), func(t *testing.T) {
			text := FormatDuration(d)
			got, err := ParseDuration(text)
			if err != nil {
				t.Fatalf("ParseDuration(%q): %v", text, err)
			}
			if got != d {
				t.Errorf("%v rendered %q which read back as %v", d, text, got)
			}
		})
	}
}

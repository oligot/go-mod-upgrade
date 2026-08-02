package module

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The units a period may be written in, beyond the ones Go itself accepts.
//
// Go's parser stops at hours, yet the periods a caller names here are days and
// weeks. Ordered longest suffix first, since "mo" has to be matched before the "m"
// of minutes: read the other way, a month becomes a minute and the value is wrong
// by a factor of forty thousand.
var units = []struct {
	suffix string
	each   time.Duration
}{
	{"mo", 30 * 24 * time.Hour},
	{"q", 90 * 24 * time.Hour},
	{"w", 7 * 24 * time.Hour},
	{"d", 24 * time.Hour},
}

// rendering is the same units ordered longest period first, which is what picking
// the largest that divides a value needs. Parsing wants them ordered by suffix
// instead, so the two orders are derived rather than written out twice.
var rendering = func() []int {
	order := make([]int, len(units))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int {
		return cmp.Compare(units[b].each, units[a].each)
	})
	return order
}()

// ParseDuration reads a period, accepting the units a person writes.
//
// "7d" is a week of settling, "2w" a fortnight, "3mo" a quarter of a year. Go's own
// units still work, so "36h" is read as it looks. A bare number is days, since that
// is the scale these periods are discussed in: --cooldown=7 and --cooldown=7d agree.
//
// A negative period is refused rather than taken literally: it would make every
// release eligible, which is the opposite of what naming a cooldown asks for.
func ParseDuration(text string) (time.Duration, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, fmt.Errorf("duration: empty, want a period such as 7d, 2w or 36h")
	}
	// A bare number is days, so the common case needs no unit at all.
	if n, err := strconv.Atoi(text); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("duration %q: negative, want a period to wait", text)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}

	// The long units are expanded into hours, which Go's own parser then reads
	// along with anything it already understands. That keeps compound values such
	// as "1w2d" and "1d12h" working without a parser of our own.
	var b strings.Builder
	rest := strings.ToLower(text)
	for rest != "" {
		digits := 0
		for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
			digits++
		}
		if digits == 0 {
			// Not a number where one belongs, so leave the remainder to Go: it
			// reports the unit it could not read.
			b.WriteString(rest)
			break
		}
		n, err := strconv.Atoi(rest[:digits])
		if err != nil {
			return 0, fmt.Errorf("duration %q: %w", text, err)
		}
		rest = rest[digits:]

		matched := false
		for _, u := range units {
			if !strings.HasPrefix(rest, u.suffix) {
				continue
			}
			b.WriteString(strconv.FormatInt(int64(time.Duration(n)*u.each/time.Hour), 10))
			b.WriteString("h")
			rest = rest[len(u.suffix):]
			matched = true
			break
		}
		if matched {
			continue
		}
		// A unit Go knows, or one it will reject by name.
		b.WriteString(strconv.Itoa(n))
		unit := 0
		for unit < len(rest) && (rest[unit] < '0' || rest[unit] > '9') {
			unit++
		}
		b.WriteString(rest[:unit])
		rest = rest[unit:]
	}

	d, err := time.ParseDuration(b.String())
	if err != nil {
		return 0, fmt.Errorf("duration %q: not a period; write it as 7d, 2w, 3mo, 1q or 36h", text)
	}
	if d < 0 {
		return 0, fmt.Errorf("duration %q: negative, want a period to wait", text)
	}
	return d, nil
}

// FormatDuration renders a period in the largest unit that divides it exactly, so a
// listing says "1w" rather than "168h0m0s".
//
// Largest rather than most familiar: 168h is both a week and seven days, and
// preferring one per unit would be a judgement to remember instead of a rule to
// apply. Below an hour Go's own rendering is already what a reader expects. What
// comes back reads back through ParseDuration, which matters because it is what a
// listing shows and a reader may paste it into a flag.
func FormatDuration(d time.Duration) string {
	if d <= 0 {
		return d.String()
	}
	for _, at := range rendering {
		u := units[at]
		// The largest unit that divides exactly wins, so 168h is a week rather than
		// seven days and 2160h a quarter rather than three months.
		if d%u.each == 0 {
			return strconv.FormatInt(int64(d/u.each), 10) + u.suffix
		}
	}
	return d.String()
}

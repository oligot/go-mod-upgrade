package module

import (
	"cmp"
	"fmt"
	"math"
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

// ApproxDuration renders a period in the largest unit that fits, to one decimal.
//
// FormatDuration renders only what divides exactly, which is right for a period a
// reader may paste back into a flag but leaves an arbitrary one -- an age, measured
// against now -- spelled as Go spells it: "309h14m42s" is arithmetic a reader has to
// do in their head to learn it means nearly thirteen days.
//
// One decimal, because the scale is the answer and the remainder is not: "12.9d"
// says what a reader deciding whether to refetch needs, where "12d" rounds away half
// a day and the seconds were never meaningful. A value that divides exactly keeps its
// plain spelling rather than gaining a needless ".0".
func ApproxDuration(d time.Duration) string {
	if d <= 0 {
		return d.String()
	}
	// A period one of the units divides exactly is already an answer, and its own
	// spelling is better than any approximation of it: 240h is "10d", not "1.4w".
	if exact := FormatDuration(d); exact != d.String() {
		return exact
	}
	// Otherwise the largest unit that fits, as FormatDuration would choose, with the
	// remainder carried as one decimal rather than dropped.
	for _, u := range append(approxUnits(),
		unit{"h", time.Hour}, unit{"m", time.Minute}) {
		if d >= u.each {
			return approx(d, u.each, u.suffix)
		}
	}
	// Under a minute, where seconds are the scale a reader wants.
	return d.Round(time.Second).String()
}

// unit is a period and how it is spelled.
type unit struct {
	suffix string
	each   time.Duration
}

// approxUnits are the long units, longest first, which is the order picking the
// largest that fits needs.
func approxUnits() []unit {
	out := make([]unit, 0, len(units))
	for _, at := range rendering {
		out = append(out, unit{units[at].suffix, units[at].each})
	}
	return out
}

// approx renders d as a multiple of each, to one decimal, dropping a decimal that
// rounded away.
//
// Rounded first and then formatted with the shortest representation, rather than
// trimming a ".0" off a fixed-width one: that spells 12.04 days "12" and 12.05 days
// "12.1", so the decimal appears only when it says something. Trimming the text
// instead would leave any other trailing zero in place.
func approx(d, each time.Duration, suffix string) string {
	tenths := math.Round(float64(d)/float64(each)*10) / 10
	return strconv.FormatFloat(tenths, 'f', -1, 64) + suffix
}

package app

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"
)

// Why a module's upgrade could not be discovered.
//
// Sentinels rather than message tests at the point of use, so a caller asks errors.Is what
// happened instead of re-deciding it from prose. The deciding happens once, in classify.
var (
	// errProxyOff is the proxy switched off, so nothing published can be discovered.
	// The toolchain treats this as a "does not exist" rather than as a network fault
	// -- see errProxyOff in cmd/go/internal/modfetch/repo.go -- which is why it is
	// established from the environment rather than recognised in a message.
	errProxyOff = errors.New("module lookup disabled by GOPROXY=off")
	// errProxyUnreachable is a proxy that could not be reached: no route, no listener, no
	// answer in time, or a certificate that could not be trusted.
	errProxyUnreachable = errors.New("proxy unreachable")
	// errLookupDisabled is the toolchain declining to look a module up, rather than
	// failing to. -mod=vendor and -mod=mod both do this.
	errLookupDisabled = errors.New("module lookup disabled")
	// errNoSuchVersion is the proxy answering about the module: the path does not exist, or
	// the version was never published. A real answer rather than a failure to get one, and
	// the one cause here that is not about reachability.
	errNoSuchVersion = errors.New("no such module or version")
)

// reach is whether this run can ask the proxy what has been published.
//
// It matters because the toolchain does not say. "go list -m -u" exits zero with nothing on
// stderr whether it asked and found nothing newer or never asked at all, and with GOPROXY=off
// the two are byte-identical per module: no Update field and no Error field, exactly like a
// module already at its newest version. A run with no network therefore reports a clean tree it
// never checked, which is the one wrong answer this tool must not give -- a pre-commit hook on a
// plane would pass every commit.
//
// So reachability is established up front instead of inferred from the output, and what could
// not be asked about is reported as unknown rather than as current.
type reach struct {
	// proxy is what the toolchain resolved GOPROXY to, for the log.
	proxy string
	// cause is why lookups cannot succeed, nil when they can.
	cause error
}

// offline reports whether this run can discover anything newer than what it already has.
func (r reach) offline() bool { return r.cause != nil }

// goproxyOff is the GOPROXY value that disables module lookups entirely. "off" always fails
// hard rather than falling through to the next entry in the list.
const goproxyOff = "off"

// proxyReach asks the toolchain whether it can reach a proxy.
//
// Asked of "go env" rather than read from the environment, because GOPROXY can also come from
// Go's own env file, where os.Getenv cannot see it: a developer who set GOPROXY=off with
// "go env -w" would otherwise be told their tree is up to date. One invocation, around 0.01s.
//
// An unset GOPROXY is not offline. It falls back to the default proxy, so an empty value means
// "the default" rather than "nowhere".
func proxyReach(ctx context.Context) reach {
	out, err := exec.CommandContext(ctx, "go", "env", "GOPROXY").Output()
	if err != nil {
		// A toolchain that cannot say is assumed reachable. Guessing offline would mark
		// every module unknown on the strength of a failure that says nothing about the
		// network, and the queries themselves are about to report their own errors.
		log.Debug().Err(err).Msg("Could not read GOPROXY, so assuming a proxy is reachable")
		return reach{}
	}
	proxy := strings.TrimSpace(string(out))
	return reachFrom(proxy)
}

// reachFrom decides what a resolved GOPROXY means.
//
// Separate from proxyReach so the decision can be exercised without a subprocess. It is the
// whole of the rule: proxyReach adds only the asking.
func reachFrom(proxy string) reach {
	r := reach{proxy: proxy}
	if proxy == goproxyOff {
		r.cause = errProxyOff
	}
	return r
}

// splitEnvLines reads the first two values "go env" printed, one per line.
//
// "go env" answers a list of names with a list of values in the order asked, one to a line, and
// prints an empty line for a variable with no value. So a missing value is a present empty
// string rather than a shorter list -- but a toolchain that printed fewer lines than expected
// would otherwise index past the end, and an empty value and an absent one mean the same thing
// to both callers here.
func splitEnvLines(out string) (first, second string) {
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	if len(lines) > 0 {
		first = strings.TrimSpace(lines[0])
	}
	if len(lines) > 1 {
		second = strings.TrimSpace(lines[1])
	}
	return first, second
}

// classify says why a per-module query failed, wrapping one of the sentinels above so a caller
// can ask errors.Is rather than matching text again.
//
// Matching text is what the boundary leaves available. "go list -m -e" reports a failure by
// folding it into its JSON output as a ModuleError, which holds a single string: whatever
// *net.OpError or syscall.Errno the toolchain saw was flattened to prose in another process
// before this one read it, so there is no value left to unwrap and no type left to assert.
// Doing it here and nowhere else keeps that to one place.
//
// The distinction that matters is not network against module but definite against indefinite. A
// version never published is a real answer, so it is recognised as one. An unrecognised message
// is neither, and the caller records it as unknown: a proxy answering 5xx, a rate limit or an
// authentication rejection says nothing about what a module has published, and reading it as
// "nothing newer" is the one wrong answer this tool must not give.
func classify(msg string) error {
	for _, known := range []struct {
		// substr is a fragment of the toolchain's message.
		substr string
		// cause is what that fragment means.
		cause error
	}{
		// The transport could not be established, or gave up.
		{"dial tcp", errProxyUnreachable},
		{"connection refused", errProxyUnreachable},
		{"no such host", errProxyUnreachable},
		{"network is unreachable", errProxyUnreachable},
		{"i/o timeout", errProxyUnreachable},
		{"timeout awaiting response headers", errProxyUnreachable},
		{"TLS handshake timeout", errProxyUnreachable},
		{"certificate is not trusted", errProxyUnreachable},
		// The toolchain declining to fetch rather than failing to.
		{"disabled by GOPROXY=off", errProxyOff},
		{"module lookup disabled", errLookupDisabled},
		// The proxy answering about the module. A definite answer, so the requirement is
		// reported as the fault it is rather than blamed on the network.
		{"unknown revision", errNoSuchVersion},
		{"no matching versions", errNoSuchVersion},
		{"does not contain package", errNoSuchVersion},
		{"repository does not exist", errNoSuchVersion},
	} {
		if strings.Contains(msg, known.substr) {
			return fmt.Errorf("%w: %s", known.cause, msg)
		}
	}
	return errors.New(msg)
}

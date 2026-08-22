package discover

import (
	"errors"
	"slices"
	"testing"
)

// recorder is a Runner that records its calls and replays canned output.
type recorder struct {
	calls   [][]string // each call as dir followed by args
	outputs [][]byte
	errs    []error
	n       int
}

func (r *recorder) run(dir string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{dir}, args...))
	i := r.n
	r.n++
	var out []byte
	if i < len(r.outputs) {
		out = r.outputs[i]
	}
	var err error
	if i < len(r.errs) {
		err = r.errs[i]
	}
	return out, err
}

func TestModulesBuildsArgs(t *testing.T) {
	r := &recorder{outputs: [][]byte{[]byte(`{"Path":"example.com/a","Version":"v1.0.0","Update":{"Version":"v1.1.0"}}`)}}
	d := Discoverer{Run: r.run, Dir: "/work/member"}

	modules, err := d.Modules()
	if err != nil {
		t.Fatalf("Modules: %v", err)
	}
	if len(modules) != 1 || modules[0].Name != "example.com/a" {
		t.Fatalf("modules = %+v, want one example.com/a", modules)
	}

	want := []string{"/work/member", "list", "-m", "-u", "-mod=readonly", "-json", "all"}
	if len(r.calls) != 1 || !slices.Equal(r.calls[0], want) {
		t.Errorf("calls = %v, want exactly one %v", r.calls, want)
	}
}

func TestModulesWrapsRunError(t *testing.T) {
	boom := errors.New("boom")
	d := Discoverer{Run: (&recorder{errs: []error{boom}}).run}
	_, err := d.Modules()
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want it to wrap %v", err, boom)
	}
}

func TestToolsBuildsArgsAndChecksEachTool(t *testing.T) {
	r := &recorder{outputs: [][]byte{
		[]byte("example.com/cmd/tool v1.2.0\nlocalonly\n"),
		[]byte("v1.3.0\n"),
	}}
	d := Discoverer{Run: r.run, Dir: "/work/member"}

	modules, err := d.Tools()
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if len(modules) != 1 {
		t.Fatalf("modules = %+v, want one", modules)
	}
	if got := modules[0].To.String(); got != "1.3.0" {
		t.Errorf("to = %q, want 1.3.0", got)
	}

	// The local tool gets no update check, so there are exactly two calls.
	wantList := []string{"/work/member", "list", "-f", toolsFormat, "tool"}
	wantCheck := []string{"/work/member", "list", "-m", "-f", toolUpdateFormat, "-u", "example.com/cmd/tool"}
	if len(r.calls) != 2 {
		t.Fatalf("calls = %v, want 2", r.calls)
	}
	if !slices.Equal(r.calls[0], wantList) {
		t.Errorf("first call = %v, want %v", r.calls[0], wantList)
	}
	if !slices.Equal(r.calls[1], wantCheck) {
		t.Errorf("second call = %v, want %v", r.calls[1], wantCheck)
	}
}

func TestToolsPropagatesRunErrorEvenWhenItMentionsMatchedNoPackages(t *testing.T) {
	// The deleted guard swallowed any error whose message contained
	// "matched no packages". It never fired — that warning goes to stderr and
	// exec.ExitError.Error() is only "exit status 1" — but if it ever had, it
	// would have hidden a real failure. Errors now always propagate.
	boom := errors.New("exit status 1: matched no packages")
	d := Discoverer{Run: (&recorder{errs: []error{boom}}).run}
	if _, err := d.Tools(); !errors.Is(err, boom) {
		t.Fatalf("error = %v, want it to wrap %v", err, boom)
	}
}

func TestToolsWithNoToolsIsEmptyAndNoError(t *testing.T) {
	// `go list ... tool` exits 0 with its warning on stderr, so stdout is
	// empty and no error is returned.
	d := Discoverer{Run: (&recorder{outputs: [][]byte{{}}}).run}
	modules, err := d.Tools()
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if len(modules) != 0 {
		t.Errorf("modules = %+v, want none", modules)
	}
}

func TestToolsSkipsAToolWhoseCheckFails(t *testing.T) {
	r := &recorder{
		outputs: [][]byte{[]byte("example.com/cmd/tool v1.2.0\n"), nil},
		errs:    []error{nil, errors.New("network down")},
	}
	d := Discoverer{Run: r.run}
	modules, err := d.Tools()
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if len(modules) != 0 {
		t.Errorf("modules = %+v, want none: a failed update check is skipped, not fatal", modules)
	}
}

func TestToolsSupportedRunsInTheModuleDir(t *testing.T) {
	r := &recorder{outputs: [][]byte{[]byte("go version go1.26.3 darwin/arm64\n")}}
	d := Discoverer{Run: r.run, Dir: "/ws/member"}
	supported, err := d.ToolsSupported()
	if err != nil {
		t.Fatalf("ToolsSupported: %v", err)
	}
	if !supported {
		t.Error("supported = false, want true for go1.26.3")
	}
	want := []string{"/ws/member", "version"}
	if len(r.calls) != 1 || !slices.Equal(r.calls[0], want) {
		t.Errorf("calls = %v, want exactly one %v", r.calls, want)
	}
}

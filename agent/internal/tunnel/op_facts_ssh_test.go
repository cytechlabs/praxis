// PRA-397: tests for the SSH server baseline probe.
//
// Three layers of coverage:
//
//  1. collectFacts() aggregation: the two normalized values land under
//     the FactsService.ingest column names, a coverage note lands under
//     the payload key it concerns, and an absent value is never emitted
//     as an empty string.
//  2. The configuration-file fallback walker: first-obtained-value
//     precedence, Include splicing, Match termination, and the refusal
//     to report a value when an earlier file could not be read.
//  3. The directive splitter and value normalizer.

package tunnel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// --------------------------------------------------------- aggregation

func TestCollectFactsEmitsSSHBaselineValues(t *testing.T) {
	c := &fakeFactsCollector{
		ssh: sshBaseline{
			PermitRootLogin:        "no",
			PasswordAuthentication: "yes",
		},
	}
	facts, partial := collectFacts(context.Background(), c)

	if facts["ssh_permit_root_login"] != "no" {
		t.Errorf("ssh_permit_root_login=%v, want no", facts["ssh_permit_root_login"])
	}
	if facts["ssh_password_authentication"] != "yes" {
		t.Errorf("ssh_password_authentication=%v, want yes", facts["ssh_password_authentication"])
	}
	if notes := sshCoverageNotes(partial); len(notes) != 0 {
		t.Errorf("unexpected ssh coverage notes: %v", notes)
	}
}

// A refresh that cannot establish a value must leave the key absent so
// the backend stores NULL, never an empty string that would compare as a
// real compliance value.
func TestCollectFactsOmitsUnavailableSSHValues(t *testing.T) {
	c := &fakeFactsCollector{
		ssh: sshBaseline{
			PermitRootLogin: "no",
			Coverage: map[string]string{
				sshPasswordAuthKey: sshCoverageNotConfigured,
			},
		},
	}
	facts, partial := collectFacts(context.Background(), c)

	if facts["ssh_permit_root_login"] != "no" {
		t.Errorf("ssh_permit_root_login=%v, want no", facts["ssh_permit_root_login"])
	}
	if _, present := facts["ssh_password_authentication"]; present {
		t.Errorf("unavailable value must be absent, got %v", facts["ssh_password_authentication"])
	}

	// The note names the setting it concerns, not the probe, so the
	// setting that WAS established still evaluates normally.
	notes := sshCoverageNotes(partial)
	if len(notes) != 1 || notes[sshPasswordAuthKey] != sshCoverageNotConfigured {
		t.Errorf("coverage notes=%v, want only %s", notes, sshPasswordAuthKey)
	}
}

// A fallback that resolves a value records no gap for it, because the
// walker only reports settings no earlier configuration could override.
func TestCollectFactsRecordsNoCoverageWhenBothResolve(t *testing.T) {
	c := &fakeFactsCollector{
		ssh: sshBaseline{
			PermitRootLogin:        "no",
			PasswordAuthentication: "no",
			Coverage:               map[string]string{},
		},
	}
	_, partial := collectFacts(context.Background(), c)

	if notes := sshCoverageNotes(partial); len(notes) != 0 {
		t.Errorf("coverage notes=%v, want none", notes)
	}
}

// A probe that fails outright still ships the rest of the inventory and
// records exactly one entry under the probe key.
func TestCollectFactsRecordsSSHProbeError(t *testing.T) {
	c := &fakeFactsCollector{
		kernel: "6.8.0-generic",
		ssh:    sshBaseline{},
		sshErr: os.ErrPermission,
	}
	facts, partial := collectFacts(context.Background(), c)

	if facts["kernel_version"] != "6.8.0-generic" {
		t.Errorf("kernel_version=%v", facts["kernel_version"])
	}
	if _, present := facts["ssh_permit_root_login"]; present {
		t.Error("failed probe must not emit a value")
	}
	// Neither setting was established, so the note is filed against the
	// probe rather than one payload key.
	entries := 0
	for _, entry := range partial {
		if entry["key"] == sshBaselineProbeKey {
			entries++
		}
	}
	if entries != 1 {
		t.Errorf("want one %s entry, got %v", sshBaselineProbeKey, partial)
	}
}

// The payload keys must match the columns FactsService.ingest accepts
// and the keys the SSH fallback collector emits.
func TestCollectFactsSSHKeysMatchIngestContract(t *testing.T) {
	c := &fakeFactsCollector{
		ssh: sshBaseline{PermitRootLogin: "no", PasswordAuthentication: "no"},
	}
	facts, _ := collectFacts(context.Background(), c)
	for _, key := range []string{"ssh_permit_root_login", "ssh_password_authentication"} {
		if _, present := facts[key]; !present {
			t.Errorf("payload is missing %q", key)
		}
	}
}

// sshCoverageNotes collects the per-setting coverage entries, keyed by the
// payload key each one concerns.
func sshCoverageNotes(partial []map[string]any) map[string]string {
	notes := map[string]string{}
	for _, entry := range partial {
		key, _ := entry["key"].(string)
		if key != sshPermitRootLoginKey && key != sshPasswordAuthKey {
			continue
		}
		note, _ := entry["error"].(string)
		notes[key] = note
	}
	return notes
}

// ------------------------------------------------------ config fallback

func writeSSHConfig(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestSSHDGlobalDirectivesReadsGlobalSection(t *testing.T) {
	dir := t.TempDir()
	path := writeSSHConfig(t, dir, "sshd_config", `
# managed by hand
Port 22
PermitRootLogin no
PasswordAuthentication no
`)
	resolved, reason := sshdGlobalDirectives(path)

	if resolved["permitrootlogin"] != "no" {
		t.Errorf("permitrootlogin=%q", resolved["permitrootlogin"])
	}
	if resolved["passwordauthentication"] != "no" {
		t.Errorf("passwordauthentication=%q", resolved["passwordauthentication"])
	}
	if reason != sshCoverageNotConfigured {
		t.Errorf("reason=%q", reason)
	}
}

// The server uses the first obtained value, so a later duplicate line
// must not be reported as the effective one.
func TestSSHDGlobalDirectivesFirstValueWins(t *testing.T) {
	dir := t.TempDir()
	path := writeSSHConfig(t, dir, "sshd_config", `
PermitRootLogin no
PermitRootLogin yes
PasswordAuthentication yes
`)
	resolved, _ := sshdGlobalDirectives(path)

	if resolved["permitrootlogin"] != "no" {
		t.Errorf("permitrootlogin=%q, want the first value", resolved["permitrootlogin"])
	}
}

// A drop-in included before the main file's own directive supplies the
// effective value, so the later main-file line must lose.
func TestSSHDGlobalDirectivesIncludeTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	writeSSHConfig(t, filepath.Join(dir, "sshd_config.d"), "50-cloud.conf", "PermitRootLogin yes\n")
	path := writeSSHConfig(t, dir, "sshd_config", `
Include `+dir+`/sshd_config.d/*.conf
PermitRootLogin no
PasswordAuthentication no
`)
	resolved, _ := sshdGlobalDirectives(path)

	if resolved["permitrootlogin"] != "yes" {
		t.Errorf("permitrootlogin=%q, want the included value", resolved["permitrootlogin"])
	}
	if resolved["passwordauthentication"] != "no" {
		t.Errorf("passwordauthentication=%q", resolved["passwordauthentication"])
	}
}

// Included files are read in sorted order, matching the server's glob
// expansion, so the lowest-numbered drop-in wins.
func TestSSHDGlobalDirectivesIncludeOrderIsSorted(t *testing.T) {
	dir := t.TempDir()
	dropins := filepath.Join(dir, "sshd_config.d")
	writeSSHConfig(t, dropins, "90-late.conf", "PermitRootLogin yes\n")
	writeSSHConfig(t, dropins, "10-early.conf", "PermitRootLogin no\n")
	path := writeSSHConfig(t, dir, "sshd_config", "Include "+dropins+"/*.conf\n")

	resolved, _ := sshdGlobalDirectives(path)
	if resolved["permitrootlogin"] != "no" {
		t.Errorf("permitrootlogin=%q, want the earliest drop-in", resolved["permitrootlogin"])
	}
}

// Directives inside a Match block are conditional. Reading them as the
// global value would report a setting that does not apply to every
// connection, so the walk stops at the block.
func TestSSHDGlobalDirectivesStopsAtMatchBlock(t *testing.T) {
	dir := t.TempDir()
	path := writeSSHConfig(t, dir, "sshd_config", `
PermitRootLogin no
Match Address 10.0.0.0/8
    PasswordAuthentication yes
`)
	resolved, reason := sshdGlobalDirectives(path)

	if resolved["permitrootlogin"] != "no" {
		t.Errorf("permitrootlogin=%q", resolved["permitrootlogin"])
	}
	if resolved["passwordauthentication"] != "" {
		t.Errorf("conditional value must not resolve, got %q", resolved["passwordauthentication"])
	}
	if reason != sshCoverageNotConfigured {
		t.Errorf("reason=%q", reason)
	}
}

// writeDanglingDropIn creates an include target that no identity can
// read, so the unreadable-file contract is exercised the same way for
// root and for an unprivileged user.
func writeDanglingDropIn(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(dir, name)
	if err := os.Symlink(filepath.Join(dir, "no-such-target"), link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := os.ReadFile(link); err == nil {
		t.Fatalf("%s unexpectedly readable", link)
	}
}

// When a file that could carry an earlier, winning value cannot be read,
// nothing after it may be claimed as effective.
func TestSSHDGlobalDirectivesRefusesWhenEarlierFileUnreadable(t *testing.T) {
	dir := t.TempDir()
	dropins := filepath.Join(dir, "sshd_config.d")
	writeDanglingDropIn(t, dropins, "10-blocked.conf")
	path := writeSSHConfig(t, dir, "sshd_config", `
Include `+dropins+`/*.conf
PermitRootLogin no
PasswordAuthentication no
`)
	resolved, reason := sshdGlobalDirectives(path)

	if resolved["permitrootlogin"] != "" {
		t.Errorf("overridable value must not resolve, got %q", resolved["permitrootlogin"])
	}
	if reason != sshCoverageConfigUnreadable {
		t.Errorf("reason=%q, want %q", reason, sshCoverageConfigUnreadable)
	}
}

// A value already resolved before the unreadable file is still
// trustworthy, because nothing read later could have overridden it.
func TestSSHDGlobalDirectivesKeepsValuesResolvedBeforeBlock(t *testing.T) {
	dir := t.TempDir()
	dropins := filepath.Join(dir, "sshd_config.d")
	writeDanglingDropIn(t, dropins, "10-blocked.conf")
	path := writeSSHConfig(t, dir, "sshd_config", `
PermitRootLogin no
Include `+dropins+`/*.conf
`)
	resolved, reason := sshdGlobalDirectives(path)

	if resolved["permitrootlogin"] != "no" {
		t.Errorf("permitrootlogin=%q, want the value resolved before the block", resolved["permitrootlogin"])
	}
	if resolved["passwordauthentication"] != "" {
		t.Errorf("passwordauthentication=%q, want unresolved", resolved["passwordauthentication"])
	}
	if reason != sshCoverageConfigUnreadable {
		t.Errorf("reason=%q, want %q", reason, sshCoverageConfigUnreadable)
	}
}

func TestSSHDGlobalDirectivesMissingFile(t *testing.T) {
	resolved, reason := sshdGlobalDirectives(filepath.Join(t.TempDir(), "absent"))

	if len(resolved) != 0 {
		t.Errorf("resolved=%v, want empty", resolved)
	}
	if reason != sshCoverageConfigUnreadable {
		t.Errorf("reason=%q, want %q", reason, sshCoverageConfigUnreadable)
	}
}

// A self-referential Include must terminate on the depth bound rather
// than recurse until the stack gives out.
func TestSSHDGlobalDirectivesBoundsIncludeRecursion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	writeSSHConfig(t, dir, "sshd_config", "Include "+path+"\n")

	resolved, reason := sshdGlobalDirectives(path)
	if len(resolved) != 0 {
		t.Errorf("resolved=%v, want empty", resolved)
	}
	if reason != sshCoverageOverridable {
		t.Errorf("reason=%q, want %q", reason, sshCoverageOverridable)
	}
}

// ----------------------------------------------------------- parsing

func TestSplitSSHDirective(t *testing.T) {
	cases := []struct {
		line  string
		key   string
		value string
		ok    bool
	}{
		{"PermitRootLogin no", "permitrootlogin", "no", true},
		{"  permitrootlogin   prohibit-password  ", "permitrootlogin", "prohibit-password", true},
		{"PasswordAuthentication=yes", "passwordauthentication", "yes", true},
		{"Match Address 10.0.0.0/8", "match", "Address 10.0.0.0/8", true},
		{"# PermitRootLogin yes", "", "", false},
		{"", "", "", false},
		{"PermitRootLogin", "", "", false},
	}
	for _, tc := range cases {
		key, value, ok := splitSSHDirective(tc.line)
		if ok != tc.ok || key != tc.key || value != tc.value {
			t.Errorf("splitSSHDirective(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.line, key, value, ok, tc.key, tc.value, tc.ok)
		}
	}
}

func TestNormalizeSSHValue(t *testing.T) {
	cases := map[string]string{
		"no":                 "no",
		"  YES  ":            "yes",
		"Prohibit-Password":  "prohibit-password",
		`"no"`:               "no",
		"no # trailing note": "no",
		"":                   "",
		"   ":                "",
	}
	for raw, want := range cases {
		if got := normalizeSSHValue(raw); got != want {
			t.Errorf("normalizeSSHValue(%q) = %q, want %q", raw, got, want)
		}
	}
}

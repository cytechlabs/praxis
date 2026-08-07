package config

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestResolveFlagWins(t *testing.T) {
	t.Setenv(EnvConfigDir, "/from/env")
	got := Resolve("/from/flag")
	if got != "/from/flag" {
		t.Fatalf("expected flag to win, got %q", got)
	}
}

func TestResolveEnvBeatsDefault(t *testing.T) {
	t.Setenv(EnvConfigDir, "/from/env")
	got := Resolve("")
	if got != "/from/env" {
		t.Fatalf("expected env, got %q", got)
	}
}

func TestResolveDefault(t *testing.T) {
	t.Setenv(EnvConfigDir, "")
	got := Resolve("")
	if got != DefaultConfigDir {
		t.Fatalf("expected %q, got %q", DefaultConfigDir, got)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := &Config{
		BackendURL: "https://praxis.example.com",
		BrokerURL:  "wss://agent-broker.example.com:8443",
		SystemID:   42,
	}
	if err := Save(dir, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if *got != *want {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}
}

func TestLoadMissingFileSurfacesError(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Fatal("expected error loading missing config, got nil")
	}
}

func TestSaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	first := &Config{BackendURL: "https://a", BrokerURL: "wss://a", SystemID: 1}
	if err := Save(dir, first); err != nil {
		t.Fatalf("save first: %v", err)
	}
	// The tmp file should not linger after a successful save.
	if _, err := os.Stat(filepath.Join(dir, ConfigFile+".tmp")); !os.IsNotExist(err) {
		t.Fatalf("tmp file lingered after save: err=%v", err)
	}
	assertNoTempLeak(t, dir, ConfigFile)
}

// assertNoTempLeak fails if any WriteFileAtomic temp file for name remains in dir.
func assertNoTempLeak(t *testing.T, dir, name string) {
	t.Helper()
	leaks, err := filepath.Glob(filepath.Join(dir, "."+name+".tmp-*"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(leaks) != 0 {
		t.Fatalf("temp files lingered: %v", leaks)
	}
}

// TestSaveOverwritesPermissiveConfigTo0600 is the PRA-262 config regression: an
// existing world-readable config.json must end at 0600 after Save.
func TestSaveOverwritesPermissiveConfigTo0600(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o666} {
		t.Run(fmt.Sprintf("%o", mode), func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, ConfigFile)
			if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
				t.Fatalf("seed config: %v", err)
			}
			// Force the exact permissive mode regardless of umask.
			if err := os.Chmod(p, mode); err != nil {
				t.Fatalf("chmod seed: %v", err)
			}
			if err := Save(dir, &Config{BackendURL: "https://x", BrokerURL: "wss://x", SystemID: 7}); err != nil {
				t.Fatalf("save: %v", err)
			}
			st, err := os.Stat(p)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if st.Mode().Perm() != 0o600 {
				t.Fatalf("config mode=%o want 0600 (was seeded %o)", st.Mode().Perm(), mode)
			}
			assertNoTempLeak(t, dir, ConfigFile)
			// Content is the new config, not the seeded stub.
			got, err := Load(dir)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if got.SystemID != 7 {
				t.Fatalf("content not replaced: %+v", got)
			}
		})
	}
}

// TestWriteFileAtomicCorrectsModeAndOwnership covers the shared helper directly:
// fresh + overwrite modes, no temp leak, and the documented same-process
// ownership (the result is owned by the writing process).
func TestWriteFileAtomicCorrectsMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.dat")

	// Fresh write lands at the requested mode.
	if err := WriteFileAtomic(p, []byte("one"), 0o600); err != nil {
		t.Fatalf("fresh write: %v", err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("fresh mode=%o want 0600", st.Mode().Perm())
	}

	// Overwrite a now-permissive file: final mode must still be 0600.
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := WriteFileAtomic(p, []byte("two"), 0o600); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("overwrite mode=%o want 0600", st.Mode().Perm())
	}
	if data, _ := os.ReadFile(p); string(data) != "two" {
		t.Fatalf("content=%q want %q", data, "two")
	}
	assertNoTempLeak(t, dir, "secret.dat")

	// Documented same-process ownership: the file is owned by this process.
	if sysStat, ok := st.Sys().(*syscall.Stat_t); ok {
		if int(sysStat.Uid) != os.Getuid() {
			t.Fatalf("owner uid=%d want %d (same-process ownership)", sysStat.Uid, os.Getuid())
		}
	}
}

// ---------------------------------------------------------------------------
// PRA-261: transactional identity-set publish (PublishSet)
// ---------------------------------------------------------------------------

// installFiles is the identity set PublishSet handles, with each file's required
// final mode.
var installFiles = []struct {
	name string
	mode os.FileMode
}{
	{CertFile, ModeCert},
	{AgentCAFile, ModeCert},
	{BrokerCAFile, ModeCert},
	{ConfigFile, ModeConfig},
}

// seedOldInstall writes a complete, coherent "previous" install (old-<name>
// content at each file's target mode) and returns the content map.
func seedOldInstall(t *testing.T, dir string) map[string]string {
	t.Helper()
	old := map[string]string{}
	for _, f := range installFiles {
		content := "old-" + f.name
		p := filepath.Join(dir, f.name)
		if err := os.WriteFile(p, []byte(content), f.mode); err != nil {
			t.Fatalf("seed %s: %v", f.name, err)
		}
		if err := os.Chmod(p, f.mode); err != nil {
			t.Fatalf("chmod seed %s: %v", f.name, err)
		}
		old[f.name] = content
	}
	return old
}

// newSet builds the FileSpec set with new-<name> content at each target mode.
func newSet() ([]FileSpec, map[string]string) {
	set := make([]FileSpec, 0, len(installFiles))
	want := map[string]string{}
	for _, f := range installFiles {
		content := "new-" + f.name
		set = append(set, FileSpec{Name: f.name, Data: []byte(content), Mode: f.mode})
		want[f.name] = content
	}
	return set, want
}

// assertInstall checks every live file has the expected content and exact mode.
func assertInstall(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	for _, f := range installFiles {
		p := filepath.Join(dir, f.name)
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", f.name, err)
		}
		if string(data) != want[f.name] {
			t.Fatalf("%s content=%q want %q", f.name, data, want[f.name])
		}
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", f.name, err)
		}
		if st.Mode().Perm() != f.mode {
			t.Fatalf("%s mode=%o want %o", f.name, st.Mode().Perm(), f.mode)
		}
	}
}

// assertNoInstallArtifacts fails if any staging temp or backup lingers. Both
// share the ".<name>.stage-*" prefix (backups are that name plus ".bak").
func assertNoInstallArtifacts(t *testing.T, dir string) {
	t.Helper()
	leaks, err := filepath.Glob(filepath.Join(dir, "*.stage-*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(leaks) != 0 {
		t.Fatalf("install artifacts lingered: %v", leaks)
	}
}

func TestPublishSetSuccessOverExistingInstall(t *testing.T) {
	dir := t.TempDir()
	seedOldInstall(t, dir)
	set, want := newSet()

	if err := PublishSet(dir, set); err != nil {
		t.Fatalf("publish: %v", err)
	}
	assertInstall(t, dir, want)
	assertNoInstallArtifacts(t, dir)
}

func TestPublishSetSuccessFreshInstall(t *testing.T) {
	dir := t.TempDir()
	set, want := newSet()

	if err := PublishSet(dir, set); err != nil {
		t.Fatalf("publish: %v", err)
	}
	assertInstall(t, dir, want)
	assertNoInstallArtifacts(t, dir)
}

// TestPublishSetStageFaultLeavesPreviousInstall injects a failure at each file's
// stage-write step and asserts the previous coherent install is untouched and no
// staging artifacts survive — nothing is published.
func TestPublishSetStageFaultLeavesPreviousInstall(t *testing.T) {
	for _, target := range installFiles {
		t.Run("stage-"+target.name, func(t *testing.T) {
			dir := t.TempDir()
			old := seedOldInstall(t, dir)
			set, _ := newSet()

			hookStageWrite = func(name string) error {
				if name == target.name {
					return fmt.Errorf("injected stage failure for %s", name)
				}
				return nil
			}
			defer func() { hookStageWrite = nil }()

			if err := PublishSet(dir, set); err == nil {
				t.Fatal("expected stage failure, got nil")
			}
			// Previous install fully intact; nothing published.
			assertInstall(t, dir, old)
			assertNoInstallArtifacts(t, dir)
		})
	}
}

// TestPublishSetPublishFaultRestoresPreviousInstall injects a failure at each
// file's publish-rename step and asserts every live file reverts to the previous
// coherent set — never a mix of old and new — with no artifacts left behind.
func TestPublishSetPublishFaultRestoresPreviousInstall(t *testing.T) {
	for _, target := range installFiles {
		t.Run("publish-"+target.name, func(t *testing.T) {
			dir := t.TempDir()
			old := seedOldInstall(t, dir)
			set, _ := newSet()

			hookPublishRename = func(name string) error {
				if name == target.name {
					return fmt.Errorf("injected publish failure for %s", name)
				}
				return nil
			}
			defer func() { hookPublishRename = nil }()

			if err := PublishSet(dir, set); err == nil {
				t.Fatal("expected publish failure, got nil")
			}
			// Even a failure on the LAST file must roll earlier files back to old.
			assertInstall(t, dir, old)
			assertNoInstallArtifacts(t, dir)
		})
	}
}

// TestPublishSetPublishFaultFreshInstallLeavesNothing: a publish failure with NO
// prior install must not leave a partially published new file behind.
func TestPublishSetPublishFaultFreshInstallLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	set, _ := newSet()

	// Fail on the last file so the first three get published, then rolled back.
	hookPublishRename = func(name string) error {
		if name == ConfigFile {
			return fmt.Errorf("injected publish failure")
		}
		return nil
	}
	defer func() { hookPublishRename = nil }()

	if err := PublishSet(dir, set); err == nil {
		t.Fatal("expected publish failure, got nil")
	}
	// No live identity files should exist — the fresh install was fully undone.
	for _, f := range installFiles {
		if _, err := os.Stat(filepath.Join(dir, f.name)); !os.IsNotExist(err) {
			t.Fatalf("%s should not exist after rolled-back fresh install: err=%v", f.name, err)
		}
	}
	assertNoInstallArtifacts(t, dir)
}

func TestPublishSetRejectsEmptySet(t *testing.T) {
	if err := PublishSet(t.TempDir(), nil); err == nil {
		t.Fatal("expected error for empty set, got nil")
	}
}

// Package config owns the on-disk layout under /etc/praxis-agent and
// the JSON config that ties an installed agent to its backend +
// broker.
//
// Path resolution precedence:
//
//  1. --config-dir CLI flag (when supplied)
//  2. PRAXIS_AGENT_CONFIG_DIR env var
//  3. DefaultConfigDir ("/etc/praxis-agent")
//
// All file modes are set explicitly here so subcommands can't drift.
// Permissions failure on the default path surfaces naturally — we
// never silently fall back to a writable temp dir, since that would
// leave an installation in an unsupported state.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultConfigDir is the production install path. Tests and dev
// invocations override via --config-dir or PRAXIS_AGENT_CONFIG_DIR.
const DefaultConfigDir = "/etc/praxis-agent"

// EnvConfigDir is the env var consulted when --config-dir is unset.
const EnvConfigDir = "PRAXIS_AGENT_CONFIG_DIR"

// Filenames inside the config dir. Centralised so subcommands and
// tests share the same constants.
const (
	KeyFile      = "agent.key"
	CertFile     = "agent.crt"
	AgentCAFile  = "agent-ca.crt"
	BrokerCAFile = "broker-ca.crt"
	ConfigFile   = "config.json"
)

// File modes. The private key AND config.json are sensitive (0600);
// certs / CA bundles are world-readable metadata (0644). PRA-262: config.json
// carries install metadata and is written 0600 via WriteFileAtomic.
const (
	ModeKey    os.FileMode = 0o600
	ModeConfig os.FileMode = 0o600
	ModeCert   os.FileMode = 0o644
	ModeDir    os.FileMode = 0o755
)

// Config is the JSON document at <dir>/config.json. Carries the
// minimum the agent needs to find its backend + broker after
// install-cert; subsequent tasks will extend this with cert metadata
// and tunable knobs.
type Config struct {
	BackendURL string `json:"backend_url"`
	BrokerURL  string `json:"broker_url"`
	SystemID   int    `json:"system_id"`
}

// Resolve picks the active config dir based on the documented
// precedence (flag > env > default). Pass the empty string when the
// CLI flag was not supplied.
func Resolve(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := os.Getenv(EnvConfigDir); v != "" {
		return v
	}
	return DefaultConfigDir
}

// Path returns <dir>/<name> for any of the well-known filenames.
func Path(dir, name string) string {
	return filepath.Join(dir, name)
}

// EnsureDir creates the config dir with ModeDir if missing. Returns
// the dir path on success so callers can chain.
func EnsureDir(dir string) (string, error) {
	if err := os.MkdirAll(dir, ModeDir); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	return dir, nil
}

// Load reads <dir>/config.json. Returns os.ErrNotExist when the file
// is absent so callers can distinguish "uninstalled" from "broken".
func Load(dir string) (*Config, error) {
	p := Path(dir, ConfigFile)
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	return &c, nil
}

// MarshalConfig renders a Config to the exact on-disk JSON bytes (indented,
// trailing newline) that Save and PublishSet write. Exposed so install-cert can
// stage config.json as part of a transactional identity set while keeping the
// file format identical to Save's.
func MarshalConfig(c *Config) ([]byte, error) {
	if c == nil {
		return nil, errors.New("nil config")
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	return append(raw, '\n'), nil
}

// Save writes <dir>/config.json atomically and with restrictive permissions.
// PRA-262: it goes through WriteFileAtomic so the file ends at exactly ModeConfig
// (0600) even when a pre-existing config.json was left world-readable — and a
// partial write can never leave an unparseable file at the final path.
func Save(dir string, c *Config) error {
	raw, err := MarshalConfig(c)
	if err != nil {
		return err
	}
	if _, err := EnsureDir(dir); err != nil {
		return err
	}
	return WriteFileAtomic(Path(dir, ConfigFile), raw, ModeConfig)
}

// FileSpec is one file in a transactional install set: its base filename (one of
// the well-known constants), its bytes, and its exact final mode.
type FileSpec struct {
	Name string
	Data []byte
	Mode os.FileMode
}

// Test-only fault-injection hooks (nil in production). config_test.go sets these
// to force a failure at a chosen file's stage-write or publish-rename step and
// assert the previous coherent set survives. Kept unexported so only in-package
// tests can reach them.
var (
	hookStageWrite    func(name string) error
	hookPublishRename func(name string) error
)

// PublishSet installs an entire identity set (agent.crt, agent-ca.crt,
// broker-ca.crt, config.json — PRA-261) into dir transactionally: either every
// file lands with its exact mode, or the directory keeps whatever coherent set it
// had before.
//
// Phase 1 (stage): every file is written to a sibling temp in dir, chmod'd to its
// mode, and fsync'd. Any failure here — including a bad marshal, ENOSPC, or a
// chmod/sync error — removes all staged temps and touches NO live file.
//
// Phase 2 (publish): for each file the current live copy (if any) is renamed
// aside to a backup, then the staged temp is renamed over the live path. Renames
// are same-directory and atomic. If any publish step fails, every file already
// published is restored from its backup (or removed when there was no prior
// file), so the previous set stays active — never a mixed old/new set. On success
// the backups are removed and the directory is fsync'd for durability.
//
// The staged temps and backups are hidden dotfiles that are always cleaned up, so
// no staging artifacts remain after success or a handled failure.
func PublishSet(dir string, set []FileSpec) error {
	if len(set) == 0 {
		return errors.New("empty install set")
	}
	if _, err := EnsureDir(dir); err != nil {
		return err
	}

	// Phase 1: stage everything.
	staged := make(map[string]string, len(set)) // Name -> temp path
	cleanupStaged := func() {
		for _, tmp := range staged {
			_ = os.Remove(tmp)
		}
	}
	for _, spec := range set {
		if hookStageWrite != nil {
			if err := hookStageWrite(spec.Name); err != nil {
				cleanupStaged()
				return fmt.Errorf("stage %s: %w", spec.Name, err)
			}
		}
		tmp, err := stageFile(dir, spec)
		if err != nil {
			cleanupStaged()
			return err
		}
		staged[spec.Name] = tmp
	}

	// Phase 2: publish with backup/rollback.
	type published struct {
		live   string
		backup string // "" when there was no prior live file
	}
	done := make([]published, 0, len(set))
	rollback := func() {
		// Restore in reverse publish order: put each backup back over the live
		// path, or drop the newly published file when there was no prior one.
		for i := len(done) - 1; i >= 0; i-- {
			p := done[i]
			if p.backup != "" {
				_ = os.Rename(p.backup, p.live)
			} else {
				_ = os.Remove(p.live)
			}
		}
		cleanupStaged()
	}

	for _, spec := range set {
		live := Path(dir, spec.Name)
		tmp := staged[spec.Name]

		var backup string
		if _, err := os.Lstat(live); err == nil {
			backup = tmp + ".bak"
			if err := os.Rename(live, backup); err != nil {
				rollback()
				return fmt.Errorf("publish backup %s: %w", spec.Name, err)
			}
		}

		if hookPublishRename != nil {
			if err := hookPublishRename(spec.Name); err != nil {
				if backup != "" {
					_ = os.Rename(backup, live) // restore the file just moved aside
				}
				rollback()
				return fmt.Errorf("publish %s: %w", spec.Name, err)
			}
		}

		if err := os.Rename(tmp, live); err != nil {
			if backup != "" {
				_ = os.Rename(backup, live)
			}
			rollback()
			return fmt.Errorf("publish rename %s: %w", spec.Name, err)
		}
		delete(staged, spec.Name) // consumed by the rename
		done = append(done, published{live: live, backup: backup})
	}

	// Success: drop backups, fsync the directory so the renames are durable.
	for _, p := range done {
		if p.backup != "" {
			_ = os.Remove(p.backup)
		}
	}
	fsyncDir(dir)
	return nil
}

// stageFile writes spec to a fresh sibling temp in dir at spec.Mode, fsync'd and
// closed, and returns its path. The temp is removed if any step fails.
func stageFile(dir string, spec FileSpec) (string, error) {
	tmp, err := os.CreateTemp(dir, "."+spec.Name+".stage-*")
	if err != nil {
		return "", fmt.Errorf("stage create %s: %w", spec.Name, err)
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(spec.Data); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("stage write %s: %w", spec.Name, err)
	}
	if err := tmp.Chmod(spec.Mode); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("stage chmod %s: %w", spec.Name, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("stage sync %s: %w", spec.Name, err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("stage close %s: %w", spec.Name, err)
	}
	ok = true
	return name, nil
}

// fsyncDir best-effort fsyncs a directory so that renames into it are durable.
// Directory fsync is unsupported on some filesystems; failures are non-fatal.
func fsyncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	_ = d.Sync()
}

// WriteFileAtomic writes data to path, guaranteeing the final file ends at
// exactly mode even when path already exists with a more permissive mode
// (PRA-262). os.WriteFile only applies a mode when it *creates* a file, so
// overwriting an existing 0644/0666 key or config left it permissive.
//
// It creates a fresh temp file in the SAME directory (so the rename is on one
// filesystem and therefore atomic), writes + fsyncs it, chmods it explicitly to
// mode, then renames it over path. The temp file is removed on any failure.
//
// Ownership: a rename replaces the inode, so the result is owned by the writing
// process's uid/gid — not the previous file's owner. In the agent install model
// these writes run as root (gen-keypair / install-cert via sudo), so the final
// owner is root:root, which is the intended owner for /etc/praxis-agent. The
// helper deliberately does not chown, so it needs no privilege and behaves
// deterministically in tests.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if _, err := EnsureDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Remove the temp file unless it is successfully renamed into place.
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()

	if _, werr := tmp.Write(data); werr != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, werr)
	}
	// Enforce the mode explicitly. os.CreateTemp already makes the temp 0600,
	// but chmod so the guarantee holds for any requested mode and never depends
	// on CreateTemp's default.
	if cerr := tmp.Chmod(mode); cerr != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpName, cerr)
	}
	if serr := tmp.Sync(); serr != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync %s: %w", tmpName, serr)
	}
	if cerr := tmp.Close(); cerr != nil {
		return fmt.Errorf("close %s: %w", tmpName, cerr)
	}
	if rerr := os.Rename(tmpName, path); rerr != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpName, path, rerr)
	}
	renamed = true
	return nil
}

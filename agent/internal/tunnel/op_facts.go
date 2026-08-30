// PRA-155 #2b-a: facts op handler.
//
// runFacts collects the locked PRA-155 v1 inventory from the host and
// returns it inline on op_complete (no per-op frame stream — the
// per-op WSS is opened/closed for the protocol but no data frames
// flow on it). Each probe is best-effort; any failure produces a
// {"key":..., "error":...} entry in partial_errors and the rest of
// the report still ships.
//
// Locked rules (PRA-155 #2b-a):
//   - No package-manager mutations. We only detect WHICH package
//     manager exists by binary presence + `--version` invocation; we
//     never run install/upgrade/refresh/etc.
//   - No network-heavy probes. Cloud metadata is a single short-
//     timeout HTTP GET to 169.254.169.254 (IMDSv1-only — no IMDSv2
//     token issuance). On any error or non-cloud network the probe
//     returns nothing and a partial_error.
//   - Only allowlisted cloud fields land in cloud_instance_metadata
//     (cloud_provider, instance_id, region, zone). Tokens, IAM creds,
//     user-data, SSH keys are NEVER fetched or stored.
//   - The inline facts payload shape MUST match what
//     FactsService.ingest expects. Backend adds source_transport +
//     system_id; nothing else needs translation.
//
// The agent runs as root for v1 (per the PRA-153 lock); /proc and
// /etc/os-release are world-readable on every distro that ships a
// kernel younger than this codebase, so probes don't need elevation.

package tunnel

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// Cloud-metadata probe budget. Enough that a real cloud host's IMDSv1
// endpoint replies (typical: <50ms intra-region) without dragging
// non-cloud hosts into a long blocking wait.
const factsCloudProbeTimeout = 750 * time.Millisecond

// IMDSv1 endpoints. We do NOT issue IMDSv2 tokens (PUT
// /latest/api/token) because that opens a credential surface; if a
// host has IMDSv2 required and v1 disabled, cloud fields land
// NULL with a partial_error and the rest of the inventory still
// ships.
const (
	imdsAWSBase = "http://169.254.169.254/latest/meta-data"
	imdsGCPBase = "http://169.254.169.254/computeMetadata/v1/instance"
)

// factsResult is the inline payload appended to op_complete. Field
// names match FactsService.ingest scalar columns + JSONB shapes
// exactly; backend serializes this dict straight into the ingest
// path with source_transport="agent".
type factsResult struct {
	SchemaVersion         int              `json:"schema_version"`
	CollectedAt           string           `json:"collected_at"`
	CPUModel              string           `json:"cpu_model,omitempty"`
	CPUCores              int              `json:"cpu_cores,omitempty"`
	RAMTotalBytes         int64            `json:"ram_total_bytes,omitempty"`
	KernelVersion         string           `json:"kernel_version,omitempty"`
	DistroID              string           `json:"distro_id,omitempty"`
	DistroRelease         string           `json:"distro_release,omitempty"`
	UptimeSeconds         int64            `json:"uptime_seconds,omitempty"`
	RebootRequired        *bool            `json:"reboot_required,omitempty"`
	PackageManager        string           `json:"package_manager,omitempty"`
	PackageManagerVersion string           `json:"package_manager_version,omitempty"`
	Virtualization        string           `json:"virtualization,omitempty"`
	SSHPermitRootLogin    string           `json:"ssh_permit_root_login,omitempty"`
	SSHPasswordAuth       string           `json:"ssh_password_authentication,omitempty"`
	CloudProvider         string           `json:"cloud_provider,omitempty"`
	CloudInstanceMetadata map[string]any   `json:"cloud_instance_metadata,omitempty"`
	Disks                 []map[string]any `json:"disks,omitempty"`
}

// factsCollector is the seam tests inject. Production builds the real
// implementation that reads /proc, runs `uname`, etc.; tests provide
// a fake that returns canned values + canned errors per probe so we
// can exercise the partial_errors aggregation path.
type factsCollector interface {
	cpuModelAndCores() (string, int, error)
	ramTotalBytes() (int64, error)
	kernelVersion() (string, error)
	distro() (string, string, error)
	uptimeSeconds() (int64, error)
	rebootRequired() (bool, error)
	packageManager() (string, string, error)
	virtualization() (string, error)
	sshBaseline() (sshBaseline, error)
	disks() ([]map[string]any, error)
	cloudMetadata(ctx context.Context) (string, map[string]any, error)
}

// defaultFactsCollector is the production implementation. Stateless;
// each call re-reads the underlying source.
type defaultFactsCollector struct{}

// runFacts is the op_type="facts" handler. The per-op WSS is already
// dialed + op_attach was sent by the dispatch loop; we don't push
// any frames on it (facts are inline on op_complete). The deferred
// conn.CloseNow() in dispatch() shuts the per-op WSS cleanly.
//
// Per the PRA-155 lock, this MUST always return success-with-extras
// when the collection itself completes, even if every probe failed —
// FactsService.ingest treats the upserted row's NULL columns +
// partial_errors as the right outcome for "agent reachable but local
// reads broken". We only return opOutcomeError() for protocol-level
// failures the agent can detect (e.g., context cancelled).
func (*opPump) runFacts(ctx context.Context, opID int, conn *websocket.Conn, raw map[string]any) opOutcome {
	_ = opID
	_ = conn
	_ = raw

	if ctx.Err() != nil {
		return opOutcomeError("op_stream_closed")
	}

	c := defaultFactsCollector{}
	facts, partialErrors := collectFacts(ctx, c)

	out := opOutcomeSuccess()
	out.extra = map[string]any{
		"facts":          facts,
		"partial_errors": partialErrors,
	}
	return out
}

// collectFacts runs every probe via “c“, accumulating partial
// errors. Exposed (lowercase but package-internal) so tests can drive
// it with a fake collector.
func collectFacts(
	ctx context.Context, c factsCollector,
) (map[string]any, []map[string]any) {
	partial := []map[string]any{}
	out := map[string]any{
		"schema_version": 1,
		"collected_at":   time.Now().UTC().Format(time.RFC3339),
	}

	partial = append(partial, collectCPU(c, out)...)

	if ram, err := c.ramTotalBytes(); err != nil {
		partial = append(partial, probeError("ram_total_bytes", err))
	} else if ram > 0 {
		out["ram_total_bytes"] = ram
	}

	if kv, err := c.kernelVersion(); err != nil {
		partial = append(partial, probeError("kernel_version", err))
	} else if kv != "" {
		out["kernel_version"] = kv
	}

	partial = append(partial, collectDistro(c, out)...)

	if up, err := c.uptimeSeconds(); err != nil {
		partial = append(partial, probeError("uptime_seconds", err))
	} else if up > 0 {
		out["uptime_seconds"] = up
	}

	if rr, err := c.rebootRequired(); err != nil {
		// Reboot probe is best-effort and a missing marker is the
		// "no reboot needed" answer on most distros — only record a
		// partial when we hit a real error (e.g. permission denied
		// reading the marker file).
		partial = append(partial, probeError("reboot_required", err))
	} else {
		out["reboot_required"] = rr
	}

	partial = append(partial, collectPackageManager(c, out)...)

	if v, err := c.virtualization(); err != nil {
		partial = append(partial, probeError("virtualization", err))
	} else if v != "" {
		out["virtualization"] = v
	}

	partial = append(partial, collectSSHBaseline(c, out)...)

	if d, err := c.disks(); err != nil {
		partial = append(partial, probeError("disks", err))
	} else if len(d) > 0 {
		out["disks"] = d
	}

	partial = append(partial, collectCloudMetadata(ctx, c, out)...)

	return out, partial
}

func probeError(key string, err error) map[string]any {
	return map[string]any{"key": key, "error": err.Error()}
}

// The probe helpers below each own one independent fact family. They write the
// keys they can establish into out and return the partial-error entries for
// what they could not, so collectFacts stays an ordered list of probes and the
// per-probe branching lives with the probe it describes. Order, keys, reason
// codes, and absence semantics are exactly what the inline blocks produced.

func collectCPU(c factsCollector, out map[string]any) []map[string]any {
	model, cores, err := c.cpuModelAndCores()
	if err != nil {
		return []map[string]any{probeError("cpu", err)}
	}
	if model != "" {
		out["cpu_model"] = model
	}
	if cores > 0 {
		out["cpu_cores"] = cores
	}
	return nil
}

func collectDistro(c factsCollector, out map[string]any) []map[string]any {
	id, rel, err := c.distro()
	if err != nil {
		return []map[string]any{probeError("distro", err)}
	}
	if id != "" {
		out["distro_id"] = id
	}
	if rel != "" {
		out["distro_release"] = rel
	}
	return nil
}

func collectPackageManager(c factsCollector, out map[string]any) []map[string]any {
	pm, ver, err := c.packageManager()
	if err != nil {
		return []map[string]any{probeError("package_manager", err)}
	}
	if pm != "" {
		out["package_manager"] = pm
	}
	if ver != "" {
		out["package_manager_version"] = ver
	}
	return nil
}

// collectSSHBaseline reports the SSH server baseline. Only values we can prove
// are effective are emitted; anything else stays absent and records why under
// the key it concerns, so downstream evaluation can tell "not collected yet"
// from "this collection could not establish it".
func collectSSHBaseline(c factsCollector, out map[string]any) []map[string]any {
	ssh, err := c.sshBaseline()
	if err != nil {
		// Whole-probe failure: neither setting was established, so the
		// note is filed against the probe rather than one payload key.
		return []map[string]any{probeError(sshBaselineProbeKey, err)}
	}
	if ssh.PermitRootLogin != "" {
		out[sshPermitRootLoginKey] = ssh.PermitRootLogin
	}
	if ssh.PasswordAuthentication != "" {
		out[sshPasswordAuthKey] = ssh.PasswordAuthentication
	}
	var partial []map[string]any
	for _, key := range sshBaselinePayloadKeys {
		if reason, gap := ssh.Coverage[key]; gap {
			partial = append(partial, map[string]any{
				"key":   key,
				"error": reason,
			})
		}
	}
	return partial
}

func collectCloudMetadata(
	ctx context.Context, c factsCollector, out map[string]any,
) []map[string]any {
	provider, md, err := c.cloudMetadata(ctx)
	if err != nil {
		// Non-cloud hosts time out here on the link-local IP. That's
		// expected, not an error worth surfacing — but we still want
		// chronic IMDS misconfig (e.g. cloud host with v1 disabled)
		// to be visible. The partial entry is enough; backend audit
		// will show the pattern across hosts.
		return []map[string]any{probeError("cloud_metadata", err)}
	}
	if provider != "" {
		out["cloud_provider"] = provider
	}
	if len(md) > 0 {
		out["cloud_instance_metadata"] = md
	}
	return nil
}

// ---------------------------------------------------------------- collectors

func (defaultFactsCollector) cpuModelAndCores() (string, int, error) {
	if runtime.GOOS != "linux" {
		return "", runtime.NumCPU(), nil
	}
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "", 0, err
	}
	defer f.Close() //nolint:errcheck
	model := ""
	cores := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// model name is repeated per-logical-core; we keep the first.
		if model == "" && strings.HasPrefix(line, "model name") {
			if i := strings.Index(line, ":"); i >= 0 {
				model = strings.TrimSpace(line[i+1:])
			}
		}
		if strings.HasPrefix(line, "processor") {
			cores++
		}
	}
	if err := scanner.Err(); err != nil {
		return model, cores, err
	}
	if cores == 0 {
		// Fallback: runtime sees scheduler-visible CPUs which on
		// Linux mirror /proc/cpuinfo's processor count except in
		// niche cgroup setups. Better than reporting zero.
		cores = runtime.NumCPU()
	}
	return model, cores, nil
}

func (defaultFactsCollector) ramTotalBytes() (int64, error) {
	if runtime.GOOS != "linux" {
		return 0, errors.New("/proc/meminfo unavailable on " + runtime.GOOS)
	}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		// MemTotal: 16234156 kB
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, errors.New("MemTotal malformed")
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, err
		}
		return kb * 1024, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("MemTotal not found")
}

func (defaultFactsCollector) kernelVersion() (string, error) {
	out, err := runCmdOutput("uname", "-r")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func (defaultFactsCollector) distro() (string, string, error) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "", "", err
	}
	defer f.Close() //nolint:errcheck
	id := ""
	verID := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		k, v, ok := splitKV(line)
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			verID = v
		}
	}
	return id, verID, scanner.Err()
}

func (defaultFactsCollector) uptimeSeconds() (int64, error) {
	if runtime.GOOS != "linux" {
		return 0, errors.New("/proc/uptime unavailable on " + runtime.GOOS)
	}
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, errors.New("/proc/uptime malformed")
	}
	// First field is "<seconds>.<centiseconds>"; we want a whole
	// integer seconds value for the API contract.
	whole := fields[0]
	if i := strings.Index(whole, "."); i >= 0 {
		whole = whole[:i]
	}
	return strconv.ParseInt(whole, 10, 64)
}

// rebootRequiredMarkers lists the well-known reboot-needed signals
// across distros. Presence of any → true. None → false. We do NOT
// run `dnf needs-restarting -r` here because it can dial a network
// (depending on plugins) and the PRA-155 lock prohibits
// network-heavy probes in the agent collector.
var rebootRequiredMarkers = []string{
	"/var/run/reboot-required",       // Debian/Ubuntu
	"/run/reboot-required",           // newer Debian/Ubuntu (same content)
	"/var/run/reboot-required.pkgs",  // also Debian/Ubuntu
	"/usr/bin/needs-restarting",      // RHEL/CentOS — binary presence is informational only
	"/var/run/yum-no-restart-needed", // legacy negative marker
}

func (defaultFactsCollector) rebootRequired() (bool, error) {
	// Positive markers — file existence means a reboot is pending.
	for _, p := range []string{
		"/var/run/reboot-required",
		"/run/reboot-required",
	} {
		if _, err := os.Stat(p); err == nil {
			return true, nil
		} else if !os.IsNotExist(err) {
			return false, err
		}
	}
	return false, nil
}

// packageManagerCandidates lists the binaries whose presence we
// treat as definitive proof of which package manager runs the host.
// Order matters: apt before dpkg, dnf before yum, since later entries
// are legacy fallbacks on the same family.
var packageManagerCandidates = []struct {
	name string
	bin  string
}{
	{"apt", "apt-get"},
	{"dnf", "dnf"},
	{"yum", "yum"},
	{"zypper", "zypper"},
	{"pacman", "pacman"},
	{"apk", "apk"},
}

func (defaultFactsCollector) packageManager() (string, string, error) {
	for _, c := range packageManagerCandidates {
		path, err := exec.LookPath(c.bin)
		if err != nil {
			continue
		}
		// `--version` is a read-only call across all listed PMs. We
		// keep stderr suppressed and accept any returncode — version
		// strings are stable across nonzero-exit edge cases (some
		// PMs print to stderr).
		out, _ := exec.Command(path, "--version").Output()
		ver := firstLine(string(out))
		return c.name, ver, nil
	}
	return "", "", errors.New("no known package manager binary on PATH")
}

func (defaultFactsCollector) virtualization() (string, error) {
	out, err := runCmdOutput("systemd-detect-virt", "--quiet=false")
	if err != nil {
		// systemd-detect-virt exits 1 on bare-metal; exec.Run treats
		// that as an error. Distinguish "not virtualized" (rc=1, "none")
		// from "tool missing" (PathError) so bare metal isn't recorded
		// as a probe failure.
		if exitErr, ok := err.(*exec.ExitError); ok {
			text := strings.TrimSpace(string(exitErr.Stderr))
			if text == "" {
				text = strings.TrimSpace(out)
			}
			if text == "none" || text == "" {
				return "none", nil
			}
		}
		// Tool genuinely missing or unrunnable — partial error.
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// ------------------------------------------------------------ ssh baseline

// sshBaselineProbeKey labels every partial_errors entry produced by the
// SSH server probe. Downstream compliance evaluation matches on this key
// to tell "this host cannot report the value" apart from "this host has
// not been collected yet".
const sshBaselineProbeKey = "ssh_config"

// sshdConfigPath is the canonical server configuration file. The file
// fallback reads it and any files it includes; nothing is written.
const sshdConfigPath = "/etc/ssh/sshd_config"

// sshdIncludeBaseDir resolves relative Include patterns, matching the
// server's own behavior for patterns that are not absolute paths.
const sshdIncludeBaseDir = "/etc/ssh"

// sshdBinaryCandidates are the absolute locations checked when sshd is
// not on PATH. A managed command's PATH frequently omits the sbin
// directories where the server binary actually lives. The list is fixed
// at compile time: no value read from the host is ever interpolated
// into an executed path.
var sshdBinaryCandidates = []string{
	"/usr/sbin/sshd",
	"/sbin/sshd",
	"/usr/local/sbin/sshd",
}

// Bounds on the configuration walk so a self-referential or pathological
// Include set cannot spin the probe.
const (
	sshdIncludeMaxDepth = 8
	sshdConfigMaxFiles  = 64
)

// sshBaselineKeys are the directives collected, keyed by the lowercased
// name `sshd -T` prints. Config-file matching is case-insensitive, so the
// same lowercased name works for both sources.
var sshBaselineKeys = []string{"permitrootlogin", "passwordauthentication"}

// Payload keys for the two settings, matching the ingest column names.
const (
	sshPermitRootLoginKey = "ssh_permit_root_login"
	sshPasswordAuthKey    = "ssh_password_authentication"
)

// sshBaselinePayloadKeys fixes the order coverage notes are emitted in, so
// a report is byte-identical across runs on the same host.
var sshBaselinePayloadKeys = []string{sshPermitRootLoginKey, sshPasswordAuthKey}

// Coverage reasons. Fixed codes only: no configuration content, and no
// host-supplied path, is ever placed in a reason string.
const (
	sshCoverageConfigUnreadable = "config_unreadable_precedence_unknown"
	sshCoverageOverridable      = "config_precedence_unknown"
	sshCoverageNotConfigured    = "directive_not_in_global_config"
)

// sshBaseline carries the two normalized server settings plus a per-setting
// explanation of anything that could not be established. An empty value
// means "no trustworthy evidence" and is never emitted as a fact.
//
// Coverage is keyed by payload key rather than by probe, so a gap in one
// setting never casts doubt on the other: a host whose configuration pins
// PermitRootLogin but leaves PasswordAuthentication to the compiled-in
// default still yields a real verdict for the first.
type sshBaseline struct {
	PermitRootLogin        string
	PasswordAuthentication string
	Coverage               map[string]string
}

// sshBaseline reports the effective PermitRootLogin and
// PasswordAuthentication settings.
//
// `sshd -T` is preferred because it prints what the server actually
// resolved. When it is unavailable the configuration files are read in
// the server's own merge order. That fallback only yields a value when
// no earlier configuration could have supplied a different one, so an
// overridden file directive is never reported as effective.
//
// Collection is read-only and never records configuration content: the
// only values that leave this function are the two normalized settings.
func (defaultFactsCollector) sshBaseline() (sshBaseline, error) {
	out := sshBaseline{Coverage: map[string]string{}}

	if effective, ok := sshdEffectiveConfig(); ok {
		out.PermitRootLogin = normalizeSSHValue(effective["permitrootlogin"])
		out.PasswordAuthentication = normalizeSSHValue(effective["passwordauthentication"])
	}
	if out.PermitRootLogin != "" && out.PasswordAuthentication != "" {
		return out, nil
	}

	// File fallback for whatever the effective read did not supply. A value
	// it yields is as trustworthy as an effective one, because the walker
	// only reports settings no earlier configuration could have overridden,
	// so a successful fallback records no coverage gap.
	resolved, reason := sshdGlobalDirectives(sshdConfigPath)
	if out.PermitRootLogin == "" {
		out.PermitRootLogin = normalizeSSHValue(resolved["permitrootlogin"])
	}
	if out.PasswordAuthentication == "" {
		out.PasswordAuthentication = normalizeSSHValue(resolved["passwordauthentication"])
	}
	if out.PermitRootLogin == "" {
		out.Coverage[sshPermitRootLoginKey] = reason
	}
	if out.PasswordAuthentication == "" {
		out.Coverage[sshPasswordAuthKey] = reason
	}
	return out, nil
}

// sshdEffectiveConfig runs the server's own configuration dump and
// returns the parsed key/value pairs. The second result is false when no
// server binary was found or the dump did not run.
func sshdEffectiveConfig() (map[string]string, bool) {
	bin := locateSSHDBinary()
	if bin == "" {
		return nil, false
	}
	out, err := exec.Command(bin, "-T").Output()
	if err != nil || len(out) == 0 {
		return nil, false
	}
	parsed := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		key, value, ok := splitSSHDirective(scanner.Text())
		if !ok {
			continue
		}
		if _, seen := parsed[key]; !seen {
			parsed[key] = value
		}
	}
	return parsed, true
}

// locateSSHDBinary returns the server binary path, or "" when none of
// the known locations holds an executable file.
func locateSSHDBinary() string {
	if path, err := exec.LookPath("sshd"); err == nil {
		return path
	}
	for _, candidate := range sshdBinaryCandidates {
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}
		return candidate
	}
	return ""
}

// sshdGlobalDirectives resolves the wanted directives from the
// configuration files in the server's merge order.
//
// Two rules make a resolved value trustworthy:
//
//   - The first occurrence of a directive wins, matching the server. A
//     later line cannot change an already-resolved value.
//   - The global section ends at the first Match block. Directives after
//     it apply only to matching connections, so they are not read.
//
// The walk stops as soon as a file that could hold an earlier, winning
// value cannot be read. Anything already resolved at that point is still
// trustworthy; anything outstanding is reported through the returned
// reason code, which is also returned when the configuration simply does
// not set a directive.
func sshdGlobalDirectives(path string) (map[string]string, string) {
	w := &sshdConfigWalk{resolved: map[string]string{}, reason: sshCoverageNotConfigured}
	w.walk(path, 0)
	return w.resolved, w.reason
}

type sshdConfigWalk struct {
	resolved map[string]string
	files    int
	stopped  bool
	reason   string
}

// complete reports whether every wanted directive already has a value,
// in which case no unread file can change the outcome.
func (w *sshdConfigWalk) complete() bool {
	for _, key := range sshBaselineKeys {
		if w.resolved[key] == "" {
			return false
		}
	}
	return true
}

// halt ends the walk with the supplied reason unless everything is
// already resolved.
func (w *sshdConfigWalk) halt(reason string) {
	w.stopped = true
	if !w.complete() {
		w.reason = reason
	}
}

func (w *sshdConfigWalk) walk(path string, depth int) {
	if w.stopped || w.complete() {
		return
	}
	if depth > sshdIncludeMaxDepth || w.files >= sshdConfigMaxFiles {
		w.halt(sshCoverageOverridable)
		return
	}
	w.files++

	// The path is the fixed configuration root or a file that root's own
	// configuration named through Include; nothing else reaches here.
	f, err := os.Open(path)
	if err != nil {
		w.halt(sshCoverageConfigUnreadable)
		return
	}
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := splitSSHDirective(scanner.Text())
		if !ok {
			continue
		}
		switch key {
		case "match":
			// Everything past here is conditional, so the global
			// section is finished for the whole merged configuration.
			w.halt(sshCoverageNotConfigured)
			return
		case "include":
			for _, included := range sshdIncludeTargets(value) {
				w.walk(included, depth+1)
				if w.stopped || w.complete() {
					return
				}
			}
		default:
			if sshBaselineWanted(key) && w.resolved[key] == "" {
				w.resolved[key] = value
				if w.complete() {
					return
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		w.halt(sshCoverageConfigUnreadable)
	}
}

// sshBaselineWanted reports whether a directive is one of the two the
// probe collects.
func sshBaselineWanted(key string) bool {
	for _, k := range sshBaselineKeys {
		if k == key {
			return true
		}
	}
	return false
}

// sshdIncludeTargets expands one Include argument list into the files it
// names, in the order the server would read them. Relative patterns
// resolve under the configuration directory.
func sshdIncludeTargets(value string) []string {
	var targets []string
	for _, pattern := range strings.Fields(value) {
		pattern = strings.Trim(pattern, `"`)
		if pattern == "" {
			continue
		}
		if !strings.HasPrefix(pattern, "/") {
			pattern = filepath.Join(sshdIncludeBaseDir, pattern)
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		sort.Strings(matches)
		targets = append(targets, matches...)
	}
	return targets
}

// splitSSHDirective parses one configuration or dump line into a
// lowercased keyword and its argument. Comments, blank lines, and lines
// without an argument are skipped. Both `Key value` and `Key=value`
// forms are accepted, matching the server's parser.
func splitSSHDirective(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	if i := strings.IndexByte(line, '='); i > 0 && !strings.ContainsAny(line[:i], " \t") {
		key := strings.ToLower(strings.TrimSpace(line[:i]))
		return key, strings.TrimSpace(line[i+1:]), key != "" && strings.TrimSpace(line[i+1:]) != ""
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", false
	}
	return strings.ToLower(fields[0]), strings.Join(fields[1:], " "), true
}

// normalizeSSHValue reduces a directive argument to the single lowercased
// token the server reports, so agent-collected values compare the same way
// regardless of how an administrator capitalized the file.
func normalizeSSHValue(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToLower(strings.Trim(fields[0], `"`))
}

func (defaultFactsCollector) disks() ([]map[string]any, error) {
	// lsblk -J emits a JSON tree we can parse without shell-quoting
	// pain. -b reports byte counts (we want raw, not human-readable).
	// -o limits the columns to the ones we persist; future-proof if
	// lsblk versions grow new defaults that bloat output.
	out, err := runCmdOutput("lsblk", "-J", "-b", "-o", "MOUNTPOINT,FSTYPE,SIZE,FSUSED,FSAVAIL")
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Blockdevices []map[string]any `json:"blockdevices"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return nil, err
	}
	disks := []map[string]any{}
	walkLsblk(parsed.Blockdevices, &disks)
	return disks, nil
}

// walkLsblk recurses through lsblk's tree (devices may have
// "children") and emits one entry per mounted filesystem.
func walkLsblk(nodes []map[string]any, out *[]map[string]any) {
	for _, n := range nodes {
		mp, _ := n["mountpoint"].(string)
		fs, _ := n["fstype"].(string)
		if mp != "" && fs != "" {
			total := lsblkInt64(n["size"])
			avail := lsblkInt64(n["fsavail"])
			// Some filesystems report fsavail; older lsblks don't.
			// total_bytes is always non-negative; free_bytes <= total.
			entry := map[string]any{
				"mountpoint":  mp,
				"filesystem":  fs,
				"total_bytes": total,
				"free_bytes":  avail,
			}
			*out = append(*out, entry)
		}
		if kids, ok := n["children"].([]any); ok {
			children := make([]map[string]any, 0, len(kids))
			for _, k := range kids {
				if m, ok := k.(map[string]any); ok {
					children = append(children, m)
				}
			}
			walkLsblk(children, out)
		}
	}
}

func lsblkInt64(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case string:
		n, _ := strconv.ParseInt(t, 10, 64)
		return n
	}
	return 0
}

func (defaultFactsCollector) cloudMetadata(ctx context.Context) (string, map[string]any, error) {
	// Two probes in sequence with a tight overall budget. AWS first
	// because it's the most common cloud the tool will see; GCP
	// second because its endpoint requires a special header that
	// won't accidentally hit AWS. Azure's IMDS requires IMDSv2-style
	// header semantics so we skip it for v1; that means Azure hosts
	// land NULL until we revisit cloud probes in a later slice.
	probeCtx, cancel := context.WithTimeout(ctx, factsCloudProbeTimeout)
	defer cancel()
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: factsCloudProbeTimeout}).DialContext,
		},
	}

	// AWS IMDSv1 (no token): direct GET works only on hosts that
	// haven't enforced IMDSv2-required mode.
	if instance, region, ok := tryAWSIMDS(probeCtx, client); ok {
		md := map[string]any{
			"cloud_provider": "aws",
			"instance_id":    instance,
		}
		if region != "" {
			md["region"] = region
		}
		return "aws", md, nil
	}

	if instance, zone, ok := tryGCPMetadata(probeCtx, client); ok {
		md := map[string]any{
			"cloud_provider": "gcp",
			"instance_id":    instance,
		}
		if zone != "" {
			md["zone"] = zone
		}
		return "gcp", md, nil
	}

	return "", nil, errors.New("no cloud metadata service responded")
}

func tryAWSIMDS(ctx context.Context, client *http.Client) (string, string, bool) {
	instance, ok := imdsGet(ctx, client, imdsAWSBase+"/instance-id", nil)
	if !ok || instance == "" {
		return "", "", false
	}
	az, _ := imdsGet(ctx, client, imdsAWSBase+"/placement/availability-zone", nil)
	region := az
	// us-east-1a → us-east-1
	if n := len(region); n > 0 {
		last := region[n-1]
		if last >= 'a' && last <= 'z' {
			region = region[:n-1]
		}
	}
	return instance, region, true
}

func tryGCPMetadata(ctx context.Context, client *http.Client) (string, string, bool) {
	headers := http.Header{"Metadata-Flavor": []string{"Google"}}
	instance, ok := imdsGet(ctx, client, imdsGCPBase+"/id", headers)
	if !ok || instance == "" {
		return "", "", false
	}
	zone, _ := imdsGet(ctx, client, imdsGCPBase+"/zone", headers)
	// GCP returns "projects/<id>/zones/<zone>"; keep just the leaf.
	if i := strings.LastIndex(zone, "/"); i >= 0 {
		zone = zone[i+1:]
	}
	return instance, zone, true
}

func imdsGet(ctx context.Context, client *http.Client, url string, hdr http.Header) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// ---------------------------------------------------------------- helpers

func runCmdOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func splitKV(line string) (string, string, bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return "", "", false
	}
	return line[:i], line[i+1:], true
}

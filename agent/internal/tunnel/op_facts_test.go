// PRA-155 #2b-a: tests for runFacts + the collector aggregation path.
//
// Two layers of coverage:
//
//  1. collectFacts() with a fake factsCollector — pins the per-probe
//     "best-effort" contract: each probe's failure produces one
//     partial_errors entry and the rest of the report still ships.
//     Also pins which keys land in the inline payload when probes
//     succeed so a refactor doesn't accidentally rename a column.
//  2. End-to-end via the dual-broker harness — pins that op_type=facts
//     dispatches through runFacts (not runStub), reports
//     op_complete(success), and includes the inline ``facts`` field
//     on the op_complete message body. The broker side captures this
//     into result_metadata; that's the wire contract /internal/agent/
//     ops/facts depends on.

package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeFactsCollector lets each test stage canned successes/errors
// per probe. Zero values mean "probe returns its zero value with
// nil error" — the production collector follows the same convention
// (e.g. uptime=0 means "couldn't read") so collectFacts treats both
// the same way.
type fakeFactsCollector struct {
	cpuModel      string
	cpuCores      int
	cpuErr        error
	ram           int64
	ramErr        error
	kernel        string
	kernelErr     error
	distroID      string
	distroVer     string
	distroErr     error
	uptime        int64
	uptimeErr     error
	rebootReq     bool
	rebootErr     error
	pmName        string
	pmVer         string
	pmErr         error
	virt          string
	virtErr       error
	ssh           sshBaseline
	sshErr        error
	disksOut      []map[string]any
	disksErr      error
	cloudProvider string
	cloudMD       map[string]any
	cloudErr      error
}

func (f *fakeFactsCollector) cpuModelAndCores() (string, int, error) {
	return f.cpuModel, f.cpuCores, f.cpuErr
}
func (f *fakeFactsCollector) ramTotalBytes() (int64, error) { return f.ram, f.ramErr }
func (f *fakeFactsCollector) kernelVersion() (string, error) {
	return f.kernel, f.kernelErr
}
func (f *fakeFactsCollector) distro() (string, string, error) {
	return f.distroID, f.distroVer, f.distroErr
}
func (f *fakeFactsCollector) uptimeSeconds() (int64, error) {
	return f.uptime, f.uptimeErr
}
func (f *fakeFactsCollector) rebootRequired() (bool, error) {
	return f.rebootReq, f.rebootErr
}
func (f *fakeFactsCollector) packageManager() (string, string, error) {
	return f.pmName, f.pmVer, f.pmErr
}
func (f *fakeFactsCollector) virtualization() (string, error) {
	return f.virt, f.virtErr
}
func (f *fakeFactsCollector) sshBaseline() (sshBaseline, error) {
	return f.ssh, f.sshErr
}
func (f *fakeFactsCollector) disks() ([]map[string]any, error) {
	return f.disksOut, f.disksErr
}
func (f *fakeFactsCollector) cloudMetadata(_ context.Context) (string, map[string]any, error) {
	return f.cloudProvider, f.cloudMD, f.cloudErr
}

func TestCollectFactsAllSuccessful(t *testing.T) {
	c := &fakeFactsCollector{
		cpuModel:      "AMD EPYC 7B12",
		cpuCores:      8,
		ram:           16 * 1024 * 1024 * 1024,
		kernel:        "5.15.0-101-generic",
		distroID:      "ubuntu",
		distroVer:     "22.04",
		uptime:        12345,
		rebootReq:     false,
		pmName:        "apt",
		pmVer:         "apt 2.4.10",
		virt:          "kvm",
		disksOut:      []map[string]any{{"mountpoint": "/", "filesystem": "ext4", "total_bytes": int64(100), "free_bytes": int64(50)}},
		cloudProvider: "aws",
		cloudMD: map[string]any{
			"cloud_provider": "aws",
			"instance_id":    "i-0123",
			"region":         "us-east-1",
		},
	}
	facts, partial := collectFacts(context.Background(), c)
	if len(partial) != 0 {
		t.Fatalf("expected no partial errors, got %v", partial)
	}
	if facts["cpu_model"] != "AMD EPYC 7B12" {
		t.Errorf("cpu_model=%v", facts["cpu_model"])
	}
	if facts["cpu_cores"] != 8 {
		t.Errorf("cpu_cores=%v", facts["cpu_cores"])
	}
	if facts["distro_id"] != "ubuntu" {
		t.Errorf("distro_id=%v", facts["distro_id"])
	}
	if facts["package_manager"] != "apt" {
		t.Errorf("package_manager=%v", facts["package_manager"])
	}
	if facts["cloud_provider"] != "aws" {
		t.Errorf("cloud_provider=%v", facts["cloud_provider"])
	}
	if facts["schema_version"] != 1 {
		t.Errorf("schema_version=%v", facts["schema_version"])
	}
	if _, ok := facts["collected_at"]; !ok {
		t.Errorf("collected_at missing")
	}
}

func TestCollectFactsBestEffortFailures(t *testing.T) {
	// Every probe fails except CPU + reboot. The expectation is that
	// CPU still lands in the payload, reboot lands as false, and
	// every failure yields exactly one partial_errors entry. A bad
	// probe MUST NOT abort the whole collection.
	c := &fakeFactsCollector{
		cpuModel:  "x86_64",
		cpuCores:  2,
		ramErr:    errors.New("MemTotal not found"),
		kernelErr: errors.New("uname missing"),
		distroErr: errors.New("/etc/os-release unreadable"),
		uptimeErr: errors.New("/proc/uptime unreadable"),
		rebootReq: false,
		pmErr:     errors.New("no package manager"),
		virtErr:   errors.New("systemd-detect-virt missing"),
		disksErr:  errors.New("lsblk missing"),
		cloudErr:  errors.New("no cloud metadata service responded"),
	}
	facts, partial := collectFacts(context.Background(), c)
	// CPU survived.
	if facts["cpu_model"] != "x86_64" {
		t.Errorf("cpu_model lost: %v", facts["cpu_model"])
	}
	// Reboot landed as false (no error for the no-marker case).
	if facts["reboot_required"] != false {
		t.Errorf("reboot_required=%v want false", facts["reboot_required"])
	}
	// Every failed probe surfaces in partial_errors.
	wantKeys := map[string]bool{
		"ram_total_bytes": true,
		"kernel_version":  true,
		"distro":          true,
		"uptime_seconds":  true,
		"package_manager": true,
		"virtualization":  true,
		"disks":           true,
		"cloud_metadata":  true,
	}
	gotKeys := map[string]bool{}
	for _, e := range partial {
		k, _ := e["key"].(string)
		gotKeys[k] = true
	}
	for k := range wantKeys {
		if !gotKeys[k] {
			t.Errorf("missing partial_errors entry for %q", k)
		}
	}
	// Successful probes do NOT show up in partial_errors.
	if gotKeys["cpu"] {
		t.Errorf("cpu shouldn't be in partial_errors when probe succeeded")
	}
}

func TestCollectFactsPartialErrorOrderMatchesProbeOrder(t *testing.T) {
	// The probe blocks were extracted into per-family helpers. Ordering is the
	// property that refactor could silently break: partial_errors is a slice,
	// so a reordered probe changes what an operator reads first. Every probe
	// fails here, so the slice must list them in exactly collection order.
	c := &fakeFactsCollector{
		cpuErr:    errors.New("cpu"),
		ramErr:    errors.New("ram"),
		kernelErr: errors.New("kernel"),
		distroErr: errors.New("distro"),
		uptimeErr: errors.New("uptime"),
		rebootErr: errors.New("reboot"),
		pmErr:     errors.New("pm"),
		virtErr:   errors.New("virt"),
		sshErr:    errors.New("ssh"),
		disksErr:  errors.New("disks"),
		cloudErr:  errors.New("cloud"),
	}
	_, partial := collectFacts(context.Background(), c)

	want := []string{
		"cpu",
		"ram_total_bytes",
		"kernel_version",
		"distro",
		"uptime_seconds",
		"reboot_required",
		"package_manager",
		"virtualization",
		sshBaselineProbeKey,
		"disks",
		"cloud_metadata",
	}
	if len(partial) != len(want) {
		t.Fatalf("partial_errors has %d entries, want %d: %v", len(partial), len(want), partial)
	}
	for i, key := range want {
		got, _ := partial[i]["key"].(string)
		if got != key {
			t.Errorf("partial_errors[%d] key=%q want %q", i, got, key)
		}
	}
}

func TestCollectFactsSSHCoverageGapsKeepTheirPosition(t *testing.T) {
	// A resolved SSH probe that could not establish one setting reports the
	// gap under the payload key it concerns, and those entries have to stay
	// between the virtualization and disks probes.
	c := &fakeFactsCollector{
		virtErr: errors.New("virt"),
		ssh: sshBaseline{
			PermitRootLogin: "no",
			Coverage: map[string]string{
				sshPasswordAuthKey: "overridable",
			},
		},
		disksErr: errors.New("disks"),
	}
	facts, partial := collectFacts(context.Background(), c)

	if facts[sshPermitRootLoginKey] != "no" {
		t.Errorf("%s=%v want \"no\"", sshPermitRootLoginKey, facts[sshPermitRootLoginKey])
	}
	if _, present := facts[sshPasswordAuthKey]; present {
		t.Errorf("%s must stay absent when coverage reports a gap", sshPasswordAuthKey)
	}
	want := []string{"virtualization", sshPasswordAuthKey, "disks"}
	if len(partial) != len(want) {
		t.Fatalf("partial_errors has %d entries, want %d: %v", len(partial), len(want), partial)
	}
	for i, key := range want {
		got, _ := partial[i]["key"].(string)
		if got != key {
			t.Errorf("partial_errors[%d] key=%q want %q", i, got, key)
		}
	}
	if reason, _ := partial[1]["error"].(string); reason != "overridable" {
		t.Errorf("coverage reason=%q want %q", reason, "overridable")
	}
}

func TestCollectFactsCloudFieldsAllowlistedOnly(t *testing.T) {
	// The collector returns a sanitized map (cloud sanitizer also
	// runs server-side, but the agent should never EMIT credential
	// keys in the first place). The fake stages the keys we expect
	// runtime probes to surface — only those four — and we assert
	// the payload carries them through verbatim with no extras.
	c := &fakeFactsCollector{
		cloudProvider: "aws",
		cloudMD: map[string]any{
			"cloud_provider": "aws",
			"instance_id":    "i-abc",
			"region":         "us-west-2",
			"zone":           "us-west-2a",
		},
	}
	facts, _ := collectFacts(context.Background(), c)
	md, ok := facts["cloud_instance_metadata"].(map[string]any)
	if !ok {
		t.Fatalf("cloud_instance_metadata missing or wrong type: %T", facts["cloud_instance_metadata"])
	}
	allowed := map[string]bool{
		"cloud_provider": true, "instance_id": true, "region": true, "zone": true,
	}
	for k := range md {
		if !allowed[k] {
			t.Errorf("cloud md leaked non-allowlisted key %q", k)
		}
	}
}

// ---------------------------------------------------------------------------
// End-to-end: op_type=facts dispatches through runFacts and the agent
// sends inline facts on op_complete (the wire contract the broker's
// /internal/agent/ops/facts depends on). We use the existing
// dual-broker harness from op_test.go.
// ---------------------------------------------------------------------------

func TestOpFactsInlineOnOpComplete(t *testing.T) {
	opComplete := make(chan map[string]any, 1)
	opAttachSeen := make(chan map[string]any, 1)

	d := &dualBroker{
		t: t,
		tunnelScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, hello map[string]any) {
			req, _ := json.Marshal(map[string]any{
				"type":         "op_request",
				"operation_id": 200,
				"op_type":      "facts",
				"params":       map[string]any{},
			})
			_ = c.Write(ctx, websocket.MessageText, req)
			nonce, _ := json.Marshal(map[string]any{
				"type":         "op_nonce",
				"operation_id": 200,
				"nonce":        "test-facts-200",
			})
			_ = c.Write(ctx, websocket.MessageText, nonce)
			for ctx.Err() == nil {
				mt, raw, err := c.Read(ctx)
				if err != nil {
					return
				}
				if mt != websocket.MessageText {
					continue
				}
				var msg map[string]any
				_ = json.Unmarshal(raw, &msg)
				if t, _ := msg["type"].(string); t == "op_complete" {
					select {
					case opComplete <- msg:
					default:
					}
				}
			}
		},
		opScript: func(t *testing.T, ctx context.Context, c *websocket.Conn, r *http.Request) {
			// Expect op_attach; agent sends nothing else on the per-
			// op WSS for facts (no streamed frames). Read until the
			// peer closes.
			mt, raw, err := c.Read(ctx)
			if err != nil || mt != websocket.MessageText {
				return
			}
			var attach map[string]any
			_ = json.Unmarshal(raw, &attach)
			select {
			case opAttachSeen <- attach:
			default:
			}
			for ctx.Err() == nil {
				if _, _, err := c.Read(ctx); err != nil {
					return
				}
			}
		},
	}
	cfg := startDualBroker(t, d)
	cancel := driveAgent(t, cfg, RunOptions{
		BackoffInitial: 50 * time.Millisecond,
		BackoffMax:     200 * time.Millisecond,
	})
	defer cancel()

	select {
	case attach := <-opAttachSeen:
		if attach["type"] != "op_attach" {
			t.Fatalf("attach type=%v", attach["type"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("never received op_attach for facts")
	}

	select {
	case msg := <-opComplete:
		if msg["outcome"] != "success" {
			t.Fatalf("outcome=%v want success; full=%v", msg["outcome"], msg)
		}
		facts, ok := msg["facts"].(map[string]any)
		if !ok {
			t.Fatalf("op_complete missing inline facts: %v", msg)
		}
		// schema_version + collected_at always land regardless of
		// per-probe success — they're set unconditionally.
		if facts["schema_version"] != float64(1) {
			t.Errorf("schema_version=%v", facts["schema_version"])
		}
		if _, ok := facts["collected_at"]; !ok {
			t.Errorf("collected_at missing from inline facts")
		}
		// partial_errors is a list (may be empty in tests with full
		// procfs available; non-empty in CI environments missing
		// systemd-detect-virt etc.).
		if _, ok := msg["partial_errors"].([]any); !ok {
			t.Errorf("partial_errors missing or wrong type: %T", msg["partial_errors"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("never received op_complete for facts")
	}
}

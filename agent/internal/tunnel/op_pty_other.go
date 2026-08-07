// Non-Linux stub. Agent target is Linux; this exists so the package
// builds on dev workstations.

//go:build !linux

package tunnel

import (
	"context"

	"github.com/coder/websocket"
)

func (p *opPump) runPty(ctx context.Context, opID int, conn *websocket.Conn, raw map[string]any) opOutcome {
	return opOutcomeError("unsupported_platform")
}

// Non-Linux stub: the agent only runs on Linux in production, but
// non-Linux builds (developer machines, cross-compile sanity) need
// the package to compile. Calling exec on a non-Linux build returns
// op_complete(error, reason="unsupported_platform").

//go:build !linux

package tunnel

import (
	"context"

	"github.com/coder/websocket"
)

func (p *opPump) runExec(ctx context.Context, opID int, conn *websocket.Conn, raw map[string]any) opOutcome {
	return opOutcomeError("unsupported_platform")
}

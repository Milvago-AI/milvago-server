package app

import (
	"net"
	"net/http"
	"time"
)

// Use the socket peer, never caller-supplied forwarding headers. The global
// ceiling bounds database work even when peers or credentials vary. A reverse
// proxy shares its peer budget; per-client fairness belongs at that trusted edge.
func (a *App) allowPublicRequest(r *http.Request, operation string, peerBudget, totalBudget int) bool {
	peer := publicPeer(r)
	now := time.Now()
	// Totals in a limiter of their own: peer keys filling the other one never evict them.
	return a.publicRate.allow(operation+" peer:"+peer, peerBudget, now) &&
		a.publicTotals.allow(operation+" total", totalBudget, now)
}

// publicPeer is the socket peer, an IPv6 one reduced to its /64: a single host is
// routinely handed a whole /64, so per-address budgets keyed on the full address
// could be multiplied at will.
func publicPeer(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	if ip := net.ParseIP(peer); ip != nil && ip.To4() == nil {
		return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return peer
}

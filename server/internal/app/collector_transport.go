package app

import (
	"context"
	"errors"
	"net"
	"time"
)

// Outbound guards shared by every collector transport (currently the Enterprise
// observability exporter). They keep a configured endpoint from reaching cloud
// metadata services, link-local or loopback addresses, both at validation time
// and again at dial time so a DNS answer cannot smuggle a forbidden address in.

// nat64 is the well-known NAT64 prefix: on a DNS64/NAT64 network 64:ff9b::a9fe:a9fe is
// the metadata address 169.254.169.254, so the embedded IPv4 is what gets judged.
var nat64 = &net.IPNet{IP: net.ParseIP("64:ff9b::"), Mask: net.CIDRMask(96, 128)}

func unwrapNAT64(ip net.IP) net.IP {
	if nat64.Contains(ip) {
		return net.IPv4(ip[12], ip[13], ip[14], ip[15])
	}
	return ip
}

func blockedCollectorIP(ip net.IP) bool {
	ip = unwrapNAT64(ip)
	return ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.Equal(net.ParseIP("100.100.100.200")) || ip.Equal(net.ParseIP("fd00:ec2::254"))
}

// publicOnlyKey marks a delivery made for an organization other than the root one.
// In Enterprise any tenant owner configures its own export endpoints; reaching the
// operator's private network, loopback or carrier-grade NAT from there turned the
// exporter into a probe of internal services, its delivery status the oracle (audit
// of 2026-09-24). The root organization is the operator's own and keeps them.
type publicOnlyKey struct{}

func withPublicOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, publicOnlyKey{}, true)
}

var carrierGradeNAT = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func nonPublicCollectorIP(ip net.IP) bool {
	ip = unwrapNAT64(ip)
	return ip.IsLoopback() || ip.IsPrivate() || carrierGradeNAT.Contains(ip)
}

func collectorDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
	if e != nil {
		return nil, e
	}
	explicitLoopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	publicOnly, _ := ctx.Value(publicOnlyKey{}).(bool)
	for _, v := range ips {
		if blockedCollectorIP(v.IP) || (unwrapNAT64(v.IP).IsLoopback() && !explicitLoopback) || (publicOnly && nonPublicCollectorIP(v.IP)) {
			return nil, errors.New("collector address is prohibited")
		}
	}
	var last error
	for _, v := range ips {
		c, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(v.IP.String(), port))
		if e == nil {
			return c, nil
		}
		last = e
	}
	if last == nil {
		last = errors.New("collector has no usable address")
	}
	return nil, last
}

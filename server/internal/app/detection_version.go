package app

import (
	"net/url"
	"strconv"
	"strings"
)

func sameServerDomain(origin, domain string) bool {
	u, e := url.Parse(origin)
	return e == nil && strings.EqualFold(u.Hostname(), domain)
}
func detectionEngineCapable(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	major, e := strconv.Atoi(parts[0])
	if e != nil {
		return false
	}
	minor, e := strconv.Atoi(parts[1])
	if e != nil {
		return false
	}
	return major > 0 || major == 0 && minor >= 5
}

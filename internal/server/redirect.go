package server

import (
	"net/url"
	"strings"
)

// safeNext implements the approved #12 plan §3.8 predicate (RFC 9700 §2.1).
func safeNext(target, origin string) string {
	for _, b := range []byte(target) {
		if b < 0x20 || b == 0x7f || b == '\\' {
			return "/"
		}
	}
	next, err := url.Parse(target)
	if err != nil || next.Scheme != "" || next.Host != "" || next.User != nil || !strings.HasPrefix(next.Path, "/") || strings.HasPrefix(target, "//") {
		return "/"
	}
	base, err := url.Parse(origin)
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil {
		return "/"
	}
	resolved := base.ResolveReference(next)
	if resolved.Scheme != base.Scheme || resolved.Host != base.Host {
		return "/"
	}
	return target
}

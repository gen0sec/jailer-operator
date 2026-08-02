// Package validate checks a policy spec before it can reach the enforcement side.
//
// Every rule here exists because the engine would otherwise accept the value
// and quietly enforce nothing: an unparseable CIDR, a direction it does not
// know, a relative path pattern that can never match a walk that starts at the
// root, or a proxy address it cannot compare against a 32-bit destination.
package validate

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/gen0sec/jailer-operator/api/v1alpha1"
)

// Spec returns every problem found, not just the first, so one bad rule does
// not hide the rest.
func Spec(s v1alpha1.JailerPolicySpec) []error {
	var errs []error

	for i, r := range s.IPRules {
		if _, err := netip.ParsePrefix(r.CIDR); err != nil {
			errs = append(errs, fmt.Errorf("ipRules[%d]: %q is not a CIDR: %w", i, r.CIDR, err))
		}
		switch r.Direction {
		case "connect", "bind":
		default:
			errs = append(errs, fmt.Errorf(
				"ipRules[%d]: direction %q is not understood; use connect or bind", i, r.Direction))
		}
	}

	for i, r := range s.FilePaths {
		if r.Pattern == "" {
			errs = append(errs, fmt.Errorf("filePaths[%d]: pattern is empty", i))
			continue
		}
		if !strings.HasPrefix(r.Pattern, "/") {
			errs = append(errs, fmt.Errorf(
				"filePaths[%d]: %q is relative; matching starts at the root so it can never match",
				i, r.Pattern))
		}
	}

	for i, r := range s.DomainRules {
		if r.Domain == "" {
			errs = append(errs, fmt.Errorf("domainRules[%d]: domain is empty", i))
		}
	}

	if s.Proxy != nil {
		errs = append(errs, validateProxy(s.Proxy.Address)...)
	}

	errs = append(errs, checkAllowRulesCanTakeEffect(s)...)

	return errs
}

func validateProxy(address string) []error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return []error{fmt.Errorf(
			"proxy.address: %q needs host:port; address and port are matched separately: %w",
			address, err)}
	}
	var errs []error
	addr, err := netip.ParseAddr(host)
	switch {
	case err != nil:
		// Nothing resolves the proxy address, so a name would never match.
		errs = append(errs, fmt.Errorf(
			"proxy.address: host %q is not an IPv4 literal; names are not resolved for the proxy", host))
	case !addr.Is4():
		errs = append(errs, fmt.Errorf("proxy.address: host %q is not IPv4", host))
	}
	if p, err := netip.ParseAddrPort(net.JoinHostPort("0.0.0.0", port)); err != nil || p.Port() == 0 {
		errs = append(errs, fmt.Errorf("proxy.address: port %q is not usable", port))
	}
	return errs
}

// permissive reports whether a flag grants the capability. Unset counts as
// granted: the CRD defaults these to true, and a flag nobody set has not been
// used to withhold anything.
func permissive(flag *bool) bool { return flag == nil || *flag }

// checkAllowRulesCanTakeEffect catches the mirror image of a deny-list.
//
// Flags are the default and rules are exceptions: the engine consults a rule
// and, finding none, falls back to the flag. So an allow rule only does
// anything when the flag withholds the capability. Under a permissive flag the
// rule is accepted, stored, and can never change an outcome -- indistinguishable
// from enforcement unless you test the kernel.
func checkAllowRulesCanTakeEffect(s v1alpha1.JailerPolicySpec) []error {
	var errs []error

	if permissive(s.Flags.AllowFileAccess) {
		for i, r := range s.FilePaths {
			if r.Allow {
				errs = append(errs, fmt.Errorf(
					"filePaths[%d]: an allow rule has no effect while allowFileAccess is true "+
						"(it defaults to true); set allowFileAccess: false to make this an allow-list",
					i))
			}
		}
	}

	if permissive(s.Flags.AllowNetwork) {
		for i, r := range s.IPRules {
			if r.Allow {
				errs = append(errs, fmt.Errorf(
					"ipRules[%d]: an allow rule has no effect while allowNetwork is true "+
						"(it defaults to true); set allowNetwork: false to make this an allow-list",
					i))
			}
		}
		for i, r := range s.DomainRules {
			if r.Allow {
				errs = append(errs, fmt.Errorf(
					"domainRules[%d]: an allow rule has no effect while allowNetwork is true "+
						"(it defaults to true); set allowNetwork: false to make this an allow-list",
					i))
			}
		}
	}

	return errs
}

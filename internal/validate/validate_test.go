package validate

import (
	"strings"
	"testing"

	"github.com/gen0sec/jailer-operator/api/v1alpha1"
)

func TestAValidSpecHasNoProblems(t *testing.T) {
	errs := Spec(v1alpha1.JailerPolicySpec{
		IPRules:     []v1alpha1.IPRule{{CIDR: "10.0.0.0/8", Direction: "connect"}},
		FilePaths:   []v1alpha1.FilePathRule{{Pattern: "/etc/*"}},
		DomainRules: []v1alpha1.DomainRule{{Domain: "api.example.com"}},
		Proxy:       &v1alpha1.ProxyConfig{Address: "10.0.0.1:3128", Required: true},
	})
	if len(errs) != 0 {
		t.Fatalf("want no problems, got %v", errs)
	}
}

func TestABadCIDRIsRejected(t *testing.T) {
	errs := Spec(v1alpha1.JailerPolicySpec{
		IPRules: []v1alpha1.IPRule{{CIDR: "10.0.0.0/64", Direction: "connect"}},
	})
	if len(errs) == 0 {
		t.Fatal("a /64 on an IPv4 address is not a usable rule")
	}
}

func TestDirectionIsRestrictedToTheTwoTheEngineKnows(t *testing.T) {
	errs := Spec(v1alpha1.JailerPolicySpec{
		IPRules: []v1alpha1.IPRule{{CIDR: "10.0.0.0/8", Direction: "egress"}},
	})
	if len(errs) == 0 {
		t.Fatal("the engine understands connect and bind; anything else is silently dropped")
	}
	if !strings.Contains(errs[0].Error(), "egress") {
		t.Errorf("the message should quote the offending value, got %v", errs[0])
	}
}

func TestARelativePathPatternIsRejected(t *testing.T) {
	// The engine walks path components from the root, so a relative pattern
	// can never match anything.
	errs := Spec(v1alpha1.JailerPolicySpec{
		FilePaths: []v1alpha1.FilePathRule{{Pattern: "etc/*"}},
	})
	if len(errs) == 0 {
		t.Fatal("a relative pattern matches nothing and should not be accepted")
	}
}

func TestProxyAddressMustCarryAPort(t *testing.T) {
	errs := Spec(v1alpha1.JailerPolicySpec{Proxy: &v1alpha1.ProxyConfig{Address: "10.0.0.1"}})
	if len(errs) == 0 {
		t.Fatal("the engine matches address and port, so a bare address is incomplete")
	}
}

func TestProxyHostMustBeAnIPv4Literal(t *testing.T) {
	// The engine compares a 32-bit address; a name would have to be resolved
	// somewhere, and nothing does that for the proxy.
	errs := Spec(v1alpha1.JailerPolicySpec{Proxy: &v1alpha1.ProxyConfig{Address: "proxy.internal:3128"}})
	if len(errs) == 0 {
		t.Fatal("a hostname proxy would never match")
	}
}

func TestEveryProblemIsReportedNotJustTheFirst(t *testing.T) {
	errs := Spec(v1alpha1.JailerPolicySpec{
		IPRules: []v1alpha1.IPRule{
			{CIDR: "nonsense", Direction: "connect"},
			{CIDR: "10.0.0.0/8", Direction: "sideways"},
		},
		FilePaths: []v1alpha1.FilePathRule{{Pattern: ""}},
	})
	if len(errs) < 3 {
		t.Fatalf("want all three problems, got %d: %v", len(errs), errs)
	}
}

func TestProblemsAreLocatedByIndex(t *testing.T) {
	errs := Spec(v1alpha1.JailerPolicySpec{
		IPRules: []v1alpha1.IPRule{
			{CIDR: "10.0.0.0/8", Direction: "connect"},
			{CIDR: "bad", Direction: "connect"},
		},
	})
	if len(errs) != 1 {
		t.Fatalf("got %v", errs)
	}
	if !strings.Contains(errs[0].Error(), "ipRules[1]") {
		t.Errorf("the message should say which rule is wrong, got %q", errs[0])
	}
}

// Flags are the default and rules are exceptions, so an allow rule only does
// something when the flag withholds the capability. Under a permissive flag it
// is a no-op that reads as enforcement -- the same shape as a map nothing ever
// reads.
func TestAllowRulesUnderAPermissiveFlagAreRejected(t *testing.T) {
	yes := true
	errs := Spec(v1alpha1.JailerPolicySpec{
		Flags:     v1alpha1.Flags{AllowFileAccess: &yes},
		FilePaths: []v1alpha1.FilePathRule{{Pattern: "/etc/*", Allow: true}},
	})
	if len(errs) == 0 {
		t.Fatal("an allow rule with allowFileAccess true can never take effect")
	}
	if !strings.Contains(errs[0].Error(), "allowFileAccess") {
		t.Errorf("the message should name the flag to change, got %q", errs[0])
	}
}

// The default is permissive, so an unset flag has the same problem.
func TestAllowRulesWithAnUnsetFlagAreRejected(t *testing.T) {
	errs := Spec(v1alpha1.JailerPolicySpec{
		IPRules: []v1alpha1.IPRule{{CIDR: "10.0.0.0/8", Direction: "connect", Allow: true}},
	})
	if len(errs) == 0 {
		t.Fatal("an allow rule under the permissive default can never take effect")
	}
}

func TestDenyRulesUnderAPermissiveFlagAreFine(t *testing.T) {
	// This is the ordinary deny-list, and the case that must keep working.
	errs := Spec(v1alpha1.JailerPolicySpec{
		IPRules:   []v1alpha1.IPRule{{CIDR: "10.0.0.0/8", Direction: "connect", Allow: false}},
		FilePaths: []v1alpha1.FilePathRule{{Pattern: "/etc/*", Allow: false}},
	})
	if len(errs) != 0 {
		t.Fatalf("a deny-list under permissive defaults is the normal case: %v", errs)
	}
}

func TestAllowRulesAreFineWhenTheFlagWithholds(t *testing.T) {
	no := false
	errs := Spec(v1alpha1.JailerPolicySpec{
		Flags:     v1alpha1.Flags{AllowFileAccess: &no, AllowNetwork: &no},
		FilePaths: []v1alpha1.FilePathRule{{Pattern: "/etc/*", Allow: true}},
		IPRules:   []v1alpha1.IPRule{{CIDR: "10.0.0.0/8", Direction: "connect", Allow: true}},
	})
	if len(errs) != 0 {
		t.Fatalf("an allow-list with the flag withheld is the intended pairing: %v", errs)
	}
}

func TestDomainAllowRulesAreGovernedByAllowNetwork(t *testing.T) {
	errs := Spec(v1alpha1.JailerPolicySpec{
		DomainRules: []v1alpha1.DomainRule{{Domain: "api.example.com", Allow: true}},
	})
	if len(errs) == 0 {
		t.Fatal("domain allow rules need allowNetwork withheld to mean anything")
	}
}

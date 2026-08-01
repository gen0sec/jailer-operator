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

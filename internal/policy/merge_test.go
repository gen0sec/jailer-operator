package policy

import (
	"testing"

	"github.com/gen0sec/jailer-operator/api/v1alpha1"
)

func b(v bool) *bool { return &v }

func named(name string, spec v1alpha1.JailerPolicySpec) v1alpha1.JailerPolicy {
	p := v1alpha1.JailerPolicy{Spec: spec}
	p.Name = name
	return p
}

// The chosen semantics: allow_x=false is a restriction, so ANDing the flags
// means any policy that withholds a capability withholds it for the pod.
func TestFlagsAreAndedSoTheMostRestrictiveWins(t *testing.T) {
	got, err := Merge([]v1alpha1.JailerPolicy{
		named("permissive", v1alpha1.JailerPolicySpec{
			Flags: v1alpha1.Flags{AllowNetwork: b(true), AllowPtrace: b(true)},
		}),
		named("strict", v1alpha1.JailerPolicySpec{
			Flags: v1alpha1.Flags{AllowNetwork: b(true), AllowPtrace: b(false)},
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Flags.AllowNetwork == nil || !*got.Flags.AllowNetwork {
		t.Error("allowNetwork: both permitted it, so it must stay true")
	}
	if got.Flags.AllowPtrace == nil || *got.Flags.AllowPtrace {
		t.Error("allowPtrace: one policy withheld it, so it must be false")
	}
}

// A flag nobody sets must not be silently invented. Defaulting an unset
// allow_x to true would hand out a capability no policy granted.
func TestAnUnsetFlagStaysUnset(t *testing.T) {
	got, err := Merge([]v1alpha1.JailerPolicy{
		named("a", v1alpha1.JailerPolicySpec{Flags: v1alpha1.Flags{AllowNetwork: b(true)}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Flags.AllowExec != nil {
		t.Errorf("allowExec was set by nobody, got %v", *got.Flags.AllowExec)
	}
}

func TestRulesFromEveryMatchingPolicyAreKept(t *testing.T) {
	got, err := Merge([]v1alpha1.JailerPolicy{
		named("a", v1alpha1.JailerPolicySpec{
			IPRules: []v1alpha1.IPRule{{CIDR: "10.0.0.0/8", Direction: "connect"}},
		}),
		named("b", v1alpha1.JailerPolicySpec{
			IPRules: []v1alpha1.IPRule{{CIDR: "1.1.1.1/32", Direction: "connect"}},
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.IPRules) != 2 {
		t.Fatalf("both policies' rules must survive the merge, got %d", len(got.IPRules))
	}
	if len(got.Sources) != 2 {
		t.Errorf("status must name every contributing policy, got %v", got.Sources)
	}
}

// The merged role determines a role id. If merge order changed the result,
// the id would churn on every reconcile and re-enroll every pod.
func TestMergeIsIndependentOfInputOrder(t *testing.T) {
	a := named("a", v1alpha1.JailerPolicySpec{
		IPRules: []v1alpha1.IPRule{{CIDR: "10.0.0.0/8", Direction: "connect"}},
		Flags:   v1alpha1.Flags{AllowNetwork: b(true)},
	})
	c := named("c", v1alpha1.JailerPolicySpec{
		IPRules: []v1alpha1.IPRule{{CIDR: "1.1.1.1/32", Direction: "connect"}},
		Flags:   v1alpha1.Flags{AllowPtrace: b(false)},
	})
	first, err := Merge([]v1alpha1.JailerPolicy{a, c})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Merge([]v1alpha1.JailerPolicy{c, a})
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Errorf("fingerprint depends on input order:\n %s\n %s",
			first.Fingerprint(), second.Fingerprint())
	}
}

// Two policies demanding different proxies cannot both be honoured. Picking
// one silently would send traffic somewhere the operator did not ask for.
func TestConflictingProxiesAreAnError(t *testing.T) {
	_, err := Merge([]v1alpha1.JailerPolicy{
		named("a", v1alpha1.JailerPolicySpec{Proxy: &v1alpha1.ProxyConfig{Address: "10.0.0.1:3128", Required: true}}),
		named("b", v1alpha1.JailerPolicySpec{Proxy: &v1alpha1.ProxyConfig{Address: "10.0.0.2:3128", Required: true}}),
	})
	if err == nil {
		t.Error("conflicting proxy addresses must surface, not be silently resolved")
	}
}

func TestIdenticalProxiesAreNotAConflict(t *testing.T) {
	got, err := Merge([]v1alpha1.JailerPolicy{
		named("a", v1alpha1.JailerPolicySpec{Proxy: &v1alpha1.ProxyConfig{Address: "10.0.0.1:3128", Required: true}}),
		named("b", v1alpha1.JailerPolicySpec{Proxy: &v1alpha1.ProxyConfig{Address: "10.0.0.1:3128", Required: true}}),
	})
	if err != nil {
		t.Fatalf("identical proxies agree: %v", err)
	}
	if got.Proxy == nil || got.Proxy.Address != "10.0.0.1:3128" {
		t.Error("the agreed proxy must be kept")
	}
}

func TestNoMatchingPolicyYieldsNoRole(t *testing.T) {
	got, err := Merge(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("no policy matched, so the pod must not be enrolled at all")
	}
}

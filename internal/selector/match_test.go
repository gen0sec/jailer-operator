package selector

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gen0sec/jailer-operator/api/v1alpha1"
)

func spec(ns, pod *metav1.LabelSelector) v1alpha1.JailerPolicySpec {
	return v1alpha1.JailerPolicySpec{NamespaceSelector: ns, PodSelector: pod}
}

func mustMatch(t *testing.T, s v1alpha1.JailerPolicySpec, ns, pod map[string]string, want bool) {
	t.Helper()
	got, err := Matches(s, Target{NamespaceLabels: ns, PodLabels: pod})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("Matches = %v, want %v", got, want)
	}
}

// apimachinery's LabelSelectorAsSelector maps nil to labels.Nothing(). Adopting
// that here would mean a policy written without a selector matches no pods --
// present, accepted, enforcing nothing. That silent no-op is the failure this
// project exists to remove, so nil means "everything" and is documented as a
// deliberate deviation.
func TestNilSelectorsMatchEverything(t *testing.T) {
	mustMatch(t, spec(nil, nil), map[string]string{"kubernetes.io/metadata.name": "prod"},
		map[string]string{"app": "web"}, true)
}

func TestEmptySelectorsMatchEverything(t *testing.T) {
	mustMatch(t, spec(&metav1.LabelSelector{}, &metav1.LabelSelector{}), nil, nil, true)
}

func TestPodSelectorMatchLabels(t *testing.T) {
	s := spec(nil, &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}})
	mustMatch(t, s, nil, map[string]string{"app": "web"}, true)
	mustMatch(t, s, nil, map[string]string{"app": "db"}, false)
	mustMatch(t, s, nil, nil, false)
}

func TestNamespaceAndPodSelectorsBothHaveToMatch(t *testing.T) {
	s := spec(
		&metav1.LabelSelector{MatchLabels: map[string]string{"tier": "prod"}},
		&metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
	)
	mustMatch(t, s, map[string]string{"tier": "prod"}, map[string]string{"app": "web"}, true)
	mustMatch(t, s, map[string]string{"tier": "dev"}, map[string]string{"app": "web"}, false)
	mustMatch(t, s, map[string]string{"tier": "prod"}, map[string]string{"app": "db"}, false)
}

func TestMatchExpressions(t *testing.T) {
	s := spec(nil, &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"web", "api"},
		}},
	})
	mustMatch(t, s, nil, map[string]string{"tier": "api"}, true)
	mustMatch(t, s, nil, map[string]string{"tier": "batch"}, false)
}

// A selector the API server would reject must not be read as "matches
// nothing": that would turn a malformed policy into a quiet no-op instead of
// something the operator can report.
func TestAnInvalidSelectorIsAnErrorNotANonMatch(t *testing.T) {
	s := spec(nil, &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: nil, // In with no values
		}},
	})
	if _, err := Matches(s, Target{}); err == nil {
		t.Error("an invalid selector must surface as an error")
	}
}

func TestSelectReturnsOnlyMatchingPolicies(t *testing.T) {
	web := v1alpha1.JailerPolicy{Spec: spec(nil, &metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "web"}})}
	web.Name = "web"
	db := v1alpha1.JailerPolicy{Spec: spec(nil, &metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "db"}})}
	db.Name = "db"
	all := v1alpha1.JailerPolicy{Spec: spec(nil, nil)}
	all.Name = "baseline"

	got, err := Select([]v1alpha1.JailerPolicy{web, db, all}, Target{PodLabels: map[string]string{"app": "web"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want the web policy and the cluster-wide one, got %d", len(got))
	}
	names := map[string]bool{got[0].Name: true, got[1].Name: true}
	if !names["web"] || !names["baseline"] {
		t.Errorf("got %v", names)
	}
}

// One malformed policy must not hide every other policy's verdict.
func TestSelectReportsAnInvalidPolicyByName(t *testing.T) {
	bad := v1alpha1.JailerPolicy{Spec: spec(nil, &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "x", Operator: metav1.LabelSelectorOpIn,
		}}})}
	bad.Name = "malformed"

	_, err := Select([]v1alpha1.JailerPolicy{bad}, Target{})
	if err == nil {
		t.Fatal("want an error")
	}
	if got := err.Error(); got == "" || !contains(got, "malformed") {
		t.Errorf("the error should name the offending policy, got %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

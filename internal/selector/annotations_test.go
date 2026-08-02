package selector

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gen0sec/jailer-operator/api/v1alpha1"
)

func target(podLabels, podAnnotations map[string]string) Target {
	return Target{PodLabels: podLabels, PodAnnotations: podAnnotations}
}

func must(t *testing.T, s v1alpha1.JailerPolicySpec, tg Target, want bool) {
	t.Helper()
	got, err := Matches(s, tg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("Matches = %v, want %v", got, want)
	}
}

// Annotations reuse the label selector shape, so matchExpressions comes along
// with matchLabels rather than being a second dialect to learn.
func TestPodAnnotationSelectorMatchesExactValues(t *testing.T) {
	s := v1alpha1.JailerPolicySpec{PodAnnotationSelector: &metav1.LabelSelector{
		MatchLabels: map[string]string{"team": "payments"}}}
	must(t, s, target(nil, map[string]string{"team": "payments"}), true)
	must(t, s, target(nil, map[string]string{"team": "search"}), false)
	must(t, s, target(nil, nil), false)
}

func TestPodAnnotationSelectorSupportsExpressions(t *testing.T) {
	s := v1alpha1.JailerPolicySpec{PodAnnotationSelector: &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "tier", Operator: metav1.LabelSelectorOpExists}}}}
	must(t, s, target(nil, map[string]string{"tier": "anything"}), true)
	must(t, s, target(nil, map[string]string{"other": "x"}), false)
}

// Labels and annotations are separate dimensions and both must hold, the same
// way namespace and pod selectors do.
func TestLabelAndAnnotationSelectorsBothHaveToMatch(t *testing.T) {
	s := v1alpha1.JailerPolicySpec{
		PodSelector:           &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		PodAnnotationSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "payments"}},
	}
	must(t, s, target(map[string]string{"app": "web"}, map[string]string{"team": "payments"}), true)
	must(t, s, target(map[string]string{"app": "web"}, map[string]string{"team": "search"}), false)
	must(t, s, target(map[string]string{"app": "db"}, map[string]string{"team": "payments"}), false)
}

func TestNamespaceAnnotationSelector(t *testing.T) {
	s := v1alpha1.JailerPolicySpec{NamespaceAnnotationSelector: &metav1.LabelSelector{
		MatchLabels: map[string]string{"env": "prod"}}}
	must(t, s, Target{NamespaceAnnotations: map[string]string{"env": "prod"}}, true)
	must(t, s, Target{NamespaceAnnotations: map[string]string{"env": "dev"}}, false)
}

// Opt-in is the ergonomic form of the same thing: one well-known key, so a
// staged rollout does not depend on getting an annotation string right in
// every policy.
func TestRequireOptInAdmitsOnlyAnnotatedPods(t *testing.T) {
	yes := true
	s := v1alpha1.JailerPolicySpec{RequireOptIn: &yes}
	must(t, s, target(nil, map[string]string{v1alpha1.AnnotationOptIn: "true"}), true)
	must(t, s, target(nil, nil), false)
	must(t, s, target(nil, map[string]string{v1alpha1.AnnotationOptIn: "false"}), false)
	// Anything other than a clear yes is not an opt-in.
	must(t, s, target(nil, map[string]string{v1alpha1.AnnotationOptIn: "yes-please"}), false)
}

func TestOptInIsOffByDefaultSoExistingPoliciesAreUnchanged(t *testing.T) {
	s := v1alpha1.JailerPolicySpec{}
	must(t, s, target(nil, nil), true)
}

// A pod may opt in and still not be selected: opt-in narrows, it never widens.
func TestOptInDoesNotOverrideTheOtherSelectors(t *testing.T) {
	yes := true
	s := v1alpha1.JailerPolicySpec{
		RequireOptIn: &yes,
		PodSelector:  &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
	}
	must(t, s, target(map[string]string{"app": "db"},
		map[string]string{v1alpha1.AnnotationOptIn: "true"}), false)
}

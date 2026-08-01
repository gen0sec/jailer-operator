// Package selector decides which policies apply to a pod.
package selector

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/gen0sec/jailer-operator/api/v1alpha1"
)

// asSelector converts a label selector, treating nil as "everything".
//
// This deviates from metav1.LabelSelectorAsSelector, which maps nil to
// labels.Nothing(). Under that rule a policy written without a selector would
// match no pods at all: present, accepted by the API server, enforcing
// nothing. A policy that omits a selector means it does not care about that
// dimension, and a cluster-wide baseline is a legitimate thing to express.
func asSelector(s *metav1.LabelSelector) (labels.Selector, error) {
	if s == nil {
		return labels.Everything(), nil
	}
	return metav1.LabelSelectorAsSelector(s)
}

// Matches reports whether a policy applies to a pod with the given labels in a
// namespace with the given labels. Both selectors have to match.
//
// A selector that cannot be parsed is an error rather than a non-match, so a
// malformed policy is something the operator can report instead of a policy
// that quietly does nothing.
func Matches(spec v1alpha1.JailerPolicySpec, nsLabels, podLabels map[string]string) (bool, error) {
	ns, err := asSelector(spec.NamespaceSelector)
	if err != nil {
		return false, fmt.Errorf("namespaceSelector: %w", err)
	}
	if !ns.Matches(labels.Set(nsLabels)) {
		return false, nil
	}

	pod, err := asSelector(spec.PodSelector)
	if err != nil {
		return false, fmt.Errorf("podSelector: %w", err)
	}
	return pod.Matches(labels.Set(podLabels)), nil
}

// Select returns the policies that apply, in no particular order. Merge sorts
// its input, so callers do not depend on the order here.
func Select(policies []v1alpha1.JailerPolicy, nsLabels, podLabels map[string]string) ([]v1alpha1.JailerPolicy, error) {
	var matched []v1alpha1.JailerPolicy
	for _, p := range policies {
		ok, err := Matches(p.Spec, nsLabels, podLabels)
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", p.Name, err)
		}
		if ok {
			matched = append(matched, p)
		}
	}
	return matched, nil
}

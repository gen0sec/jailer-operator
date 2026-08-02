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

// Target is everything about a pod a policy can select on.
type Target struct {
	NamespaceLabels      map[string]string
	NamespaceAnnotations map[string]string
	PodLabels            map[string]string
	PodAnnotations       map[string]string
}

// Matches reports whether a policy applies to a target. Every selector the
// policy sets has to match: they narrow, never widen.
//
// A selector that cannot be parsed is an error rather than a non-match, so a
// malformed policy is something the operator can report instead of a policy
// that quietly does nothing.
func Matches(spec v1alpha1.JailerPolicySpec, t Target) (bool, error) {
	// Opt-in is checked first: it is the cheapest to evaluate and the most
	// likely reason a pod is out of scope during a staged rollout.
	if spec.RequireOptIn != nil && *spec.RequireOptIn {
		if t.PodAnnotations[v1alpha1.AnnotationOptIn] != "true" {
			return false, nil
		}
	}

	for _, dimension := range []struct {
		name     string
		selector *metav1.LabelSelector
		against  map[string]string
	}{
		{"namespaceSelector", spec.NamespaceSelector, t.NamespaceLabels},
		{"namespaceAnnotationSelector", spec.NamespaceAnnotationSelector, t.NamespaceAnnotations},
		{"podSelector", spec.PodSelector, t.PodLabels},
		{"podAnnotationSelector", spec.PodAnnotationSelector, t.PodAnnotations},
	} {
		matcher, err := asSelector(dimension.selector)
		if err != nil {
			return false, fmt.Errorf("%s: %w", dimension.name, err)
		}
		// labels.Set is only a map[string]string, so the same matcher works
		// over annotations without a parallel implementation.
		if !matcher.Matches(labels.Set(dimension.against)) {
			return false, nil
		}
	}
	return true, nil
}

// Select returns the policies that apply, in no particular order. Merge sorts
// its input, so callers do not depend on the order here.
func Select(policies []v1alpha1.JailerPolicy, t Target) ([]v1alpha1.JailerPolicy, error) {
	var matched []v1alpha1.JailerPolicy
	for _, p := range policies {
		ok, err := Matches(p.Spec, t)
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", p.Name, err)
		}
		if ok {
			matched = append(matched, p)
		}
	}
	return matched, nil
}

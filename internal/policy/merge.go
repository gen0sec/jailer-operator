// Package policy combines the JailerPolicy objects that match a pod into the
// single role jailer can enforce.
//
// jailer gives a cgroup exactly one role, while label selectors are
// many-to-many, so several policies can match one pod. They are merged rather
// than ranked: every matching policy contributes, and no policy silently does
// nothing.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/gen0sec/jailer-operator/api/v1alpha1"
)

// Effective is the role a pod is enrolled with.
type Effective struct {
	Flags       v1alpha1.Flags
	FilePaths   []v1alpha1.FilePathRule
	IPRules     []v1alpha1.IPRule
	DomainRules []v1alpha1.DomainRule
	Proxy       *v1alpha1.ProxyConfig
	// Sources names the policies that contributed, so status can explain
	// where an effective role came from. It is deliberately excluded from
	// the fingerprint: two pods whose merged rules are identical should
	// share a role id even if different policies produced them.
	Sources []string
}

// restrict ANDs one flag. A flag is permissive by name, so false is a
// restriction and propagates. A policy that leaves a flag unset is silent
// about it rather than granting it, so nil carries no opinion.
func restrict(current, incoming *bool) *bool {
	if current == nil {
		return incoming
	}
	if incoming == nil {
		return current
	}
	v := *current && *incoming
	return &v
}

// Merge combines matching policies. Rules concatenate; flags are ANDed so the
// most restrictive matching policy wins. Returns nil when nothing matched:
// the pod is then not enrolled at all, rather than enrolled with an empty
// role that would look like enforcement.
func Merge(policies []v1alpha1.JailerPolicy) (*Effective, error) {
	if len(policies) == 0 {
		return nil, nil
	}

	// The merged role determines a role id. Sorting makes the result
	// independent of the order the informer happened to deliver policies in,
	// so the id does not churn and pods are not re-enrolled for no reason.
	sorted := append([]v1alpha1.JailerPolicy(nil), policies...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	e := &Effective{}
	for _, p := range sorted {
		e.Sources = append(e.Sources, p.Name)

		e.Flags.AllowFileAccess = restrict(e.Flags.AllowFileAccess, p.Spec.Flags.AllowFileAccess)
		e.Flags.AllowNetwork = restrict(e.Flags.AllowNetwork, p.Spec.Flags.AllowNetwork)
		e.Flags.AllowExec = restrict(e.Flags.AllowExec, p.Spec.Flags.AllowExec)
		e.Flags.AllowSetuid = restrict(e.Flags.AllowSetuid, p.Spec.Flags.AllowSetuid)
		e.Flags.AllowPtrace = restrict(e.Flags.AllowPtrace, p.Spec.Flags.AllowPtrace)

		e.FilePaths = append(e.FilePaths, p.Spec.FilePaths...)
		e.IPRules = append(e.IPRules, p.Spec.IPRules...)
		e.DomainRules = append(e.DomainRules, p.Spec.DomainRules...)

		if p.Spec.Proxy != nil {
			if e.Proxy == nil {
				proxy := *p.Spec.Proxy
				e.Proxy = &proxy
			} else if *e.Proxy != *p.Spec.Proxy {
				// Egress can only be forced through one proxy. Choosing
				// between them would send traffic somewhere nobody asked for.
				return nil, fmt.Errorf(
					"policies disagree on the proxy: %q wants %s, another wants %s",
					p.Name, p.Spec.Proxy.Address, e.Proxy.Address)
			}
		}
	}

	// Canonical order, so the same set of rules always fingerprints the same.
	// Safe because every rule kind lands in a hash map on the jailer side,
	// where order carries no meaning.
	sort.Slice(e.FilePaths, func(i, j int) bool { return keyOf(e.FilePaths[i]) < keyOf(e.FilePaths[j]) })
	sort.Slice(e.IPRules, func(i, j int) bool { return keyOf(e.IPRules[i]) < keyOf(e.IPRules[j]) })
	sort.Slice(e.DomainRules, func(i, j int) bool { return keyOf(e.DomainRules[i]) < keyOf(e.DomainRules[j]) })

	return e, nil
}

func keyOf(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// Fingerprint is a stable identity for an effective role, used to allocate a
// role id that does not change unless the merged policy changes.
func (e *Effective) Fingerprint() string {
	if e == nil {
		return ""
	}
	canonical := struct {
		Flags       v1alpha1.Flags
		FilePaths   []v1alpha1.FilePathRule
		IPRules     []v1alpha1.IPRule
		DomainRules []v1alpha1.DomainRule
		Proxy       *v1alpha1.ProxyConfig
	}{e.Flags, e.FilePaths, e.IPRules, e.DomainRules, e.Proxy}

	b, err := json.Marshal(canonical)
	if err != nil {
		// Marshalling plain structs cannot fail; if it somehow does, a
		// distinct value is safer than a collision with a real role.
		return "unfingerprintable"
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

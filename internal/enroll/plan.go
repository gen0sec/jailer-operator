// Package enroll turns a pod plus the policies that match it into the
// enrollment the node agent applies.
//
// The enrollment names the pod slice, never a container scope. A container's
// cgroup carries an id that changes on every restart, so an enrollment naming
// it lapses silently on any rollout; the pod slice is derivable as soon as the
// pod is scheduled and covers every container beneath it.
package enroll

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/gen0sec/jailer-operator/api/v1alpha1"
	"github.com/gen0sec/jailer-operator/internal/cgroup"
	"github.com/gen0sec/jailer-operator/internal/policy"
	"github.com/gen0sec/jailer-operator/internal/selector"
)

// Pod is the part of a pod this decision needs.
type Pod struct {
	UID         string
	Namespace   string
	Name        string
	QoSClass    string
	Labels      map[string]string
	Annotations map[string]string
}

// Enrollment is what the agent sends to the jailer daemon.
type Enrollment struct {
	CgroupPath string
	PodID      uint64
	RoleID     uint32
	Effective  *policy.Effective
}

// IDAllocator assigns a role id to an effective policy.
type IDAllocator interface {
	Allocate(fingerprint string) (uint32, error)
}

// podID derives a stable identifier from the pod UID. The engine treats 0 as
// "not enrolled", so it is never produced.
func podID(uid string) uint64 {
	sum := sha256.Sum256([]byte(uid))
	id := binary.BigEndian.Uint64(sum[:8])
	if id == 0 {
		return 1
	}
	return id
}

// Plan returns the enrollment for a pod, or nil if no policy applies.
//
// Returning nil rather than an empty role matters: a pod enrolled with a role
// that permits everything looks enforced from the outside and is not.
func Plan(pod Pod, namespace selector.Target, policies []v1alpha1.JailerPolicy,
	root string, driver cgroup.Driver, ids IDAllocator) (*Enrollment, error) {

	matched, err := selector.Select(policies, selector.Target{
		NamespaceLabels:      namespace.NamespaceLabels,
		NamespaceAnnotations: namespace.NamespaceAnnotations,
		PodLabels:            pod.Labels,
		PodAnnotations:       pod.Annotations,
	})
	if err != nil {
		return nil, fmt.Errorf("pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}
	if len(matched) == 0 {
		return nil, nil
	}

	// Checked before merging so the message names the pod rather than
	// surfacing as a confusing path error later.
	if pod.UID == "" {
		return nil, fmt.Errorf("pod %s/%s has no UID yet", pod.Namespace, pod.Name)
	}
	if pod.QoSClass == "" {
		return nil, fmt.Errorf(
			"pod %s/%s has no QoS class yet, so its cgroup path is not yet determined",
			pod.Namespace, pod.Name)
	}

	effective, err := policy.Merge(matched)
	if err != nil {
		return nil, fmt.Errorf("pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}

	path, err := cgroup.PodSlice(root, driver, pod.QoSClass, pod.UID)
	if err != nil {
		return nil, fmt.Errorf("pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}

	// The role is the policy, not the pod: every pod under the same effective
	// policy shares one, so a few hundred pods do not exhaust the 1024 the
	// engine can hold.
	roleID, err := ids.Allocate(effective.Fingerprint())
	if err != nil {
		return nil, fmt.Errorf("pod %s/%s: %w", pod.Namespace, pod.Name, err)
	}

	return &Enrollment{
		CgroupPath: path,
		PodID:      podID(pod.UID),
		RoleID:     roleID,
		Effective:  effective,
	}, nil
}

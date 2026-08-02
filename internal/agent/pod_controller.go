// Package agent enrolls the pods scheduled to one node.
//
// Enrollment is per-node because a cgroup path only exists on the host the pod
// runs on. The agent enrolls the pod slice rather than a container scope: a
// scope's name carries a container id that changes on every restart, so an
// enrollment naming one lapses silently on any rollout, while the pod slice is
// derivable as soon as the pod is scheduled and covers every container beneath
// it.
package agent

import (
	"context"
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/gen0sec/jailer-operator/api/v1alpha1"
	"github.com/gen0sec/jailer-operator/internal/cgroup"
	"github.com/gen0sec/jailer-operator/internal/enroll"
	"github.com/gen0sec/jailer-operator/internal/jailer"
	"github.com/gen0sec/jailer-operator/internal/policy"
)

// Enroller is the part of the jailer daemon client the agent uses.
type Enroller interface {
	// DefineRole installs the role, which must happen before an enrollment
	// names it: the daemon only knows roles from the policy file it started
	// with, and refuses an unknown id.
	DefineRole(ctx context.Context, role jailer.Role) error
	EnrollCgroup(ctx context.Context, cgroupPath string, podID uint64, roleID uint32) error
	RemoveCgroup(ctx context.Context, cgroupPath string) error
}

// PodReconciler enrolls pods on this node and marks them once the daemon
// accepts.
type PodReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	NodeName   string
	CgroupRoot string
	Driver     cgroup.Driver
	Jailer     Enroller
	IDs        enroll.IDAllocator
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=jailer.gen0sec.com,resources=jailerpolicies,verbs=get;list;watch

func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Each agent owns one node: a pod scheduled elsewhere has no cgroup here,
	// and enrolling it would name a path that does not exist on this host.
	if pod.Spec.NodeName != r.NodeName {
		return ctrl.Result{}, nil
	}

	var namespace corev1.Namespace
	if err := r.Get(ctx, client.ObjectKey{Name: pod.Namespace}, &namespace); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var policies v1alpha1.JailerPolicyList
	if err := r.List(ctx, &policies); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing policies: %w", err)
	}

	plan, err := enroll.Plan(enroll.Pod{
		UID:       string(pod.UID),
		Namespace: pod.Namespace,
		Name:      pod.Name,
		QoSClass:  string(pod.Status.QOSClass),
		Labels:    pod.Labels,
	}, namespace.Labels, policies.Items, r.CgroupRoot, r.Driver, r.IDs)

	if err != nil {
		// A pod that is not yet scheduled has no QoS class, so its path is not
		// knowable. That is a wait, not a failure: the pod's own update will
		// bring the agent back.
		if pod.Status.QOSClass == "" {
			logger.V(1).Info("pod not scheduled yet, waiting", "pod", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if plan == nil {
		// No policy applies. Marking it would make an unenrolled pod count as
		// enforced.
		return ctrl.Result{}, nil
	}

	// The role has to exist before anything names it.
	if err := r.Jailer.DefineRole(ctx, roleFor(plan.RoleID, plan.Effective)); err != nil {
		return ctrl.Result{}, fmt.Errorf("defining role %d for %s: %w", plan.RoleID, req.NamespacedName, err)
	}

	if err := r.Jailer.EnrollCgroup(ctx, plan.CgroupPath, plan.PodID, plan.RoleID); err != nil {
		// Surfaced so the agent retries with backoff. The pod stays unmarked,
		// so the policy reports fewer enrolled than matched -- which is
		// exactly what an operator needs to see.
		return ctrl.Result{}, fmt.Errorf("enrolling %s: %w", req.NamespacedName, err)
	}

	return ctrl.Result{}, r.mark(ctx, &pod, plan.RoleID)
}

// mark records the role on the pod once the daemon has accepted it. The
// controller counts this annotation, so writing it earlier would report policy
// in force before anything reached a map.
func (r *PodReconciler) mark(ctx context.Context, pod *corev1.Pod, roleID uint32) error {
	want := strconv.FormatUint(uint64(roleID), 10)
	if pod.Annotations[v1alpha1.AnnotationEnrolledRole] == want {
		return nil
	}

	base := pod.DeepCopy()
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[v1alpha1.AnnotationEnrolledRole] = want
	// Patched rather than updated: pods are written by the kubelet constantly,
	// and an Update here would lose races it does not need to enter.
	return r.Patch(ctx, pod, client.MergeFrom(base))
}

// SetupWithManager watches only the pods on this node.
func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)
}

// roleFor converts a merged policy into the daemon's role shape.
//
// A flag no policy set is sent as false. The daemon has no notion of unset,
// and false is the restrictive reading: a capability nobody granted is not
// granted.
func roleFor(id uint32, e *policy.Effective) jailer.Role {
	on := func(v *bool) bool { return v != nil && *v }

	role := jailer.Role{
		ID:   id,
		Name: fmt.Sprintf("jailer-%d", id),
		Flags: jailer.Flags{
			AllowFileAccess: on(e.Flags.AllowFileAccess),
			AllowNetwork:    on(e.Flags.AllowNetwork),
			AllowExec:       on(e.Flags.AllowExec),
			AllowSetuid:     on(e.Flags.AllowSetuid),
			AllowPtrace:     on(e.Flags.AllowPtrace),
		},
	}
	for _, p := range e.FilePaths {
		role.FilePaths = append(role.FilePaths, jailer.PathPattern{Pattern: p.Pattern, Allow: p.Allow})
	}
	for _, r := range e.IPRules {
		role.IPRules = append(role.IPRules, jailer.IPRule{CIDR: r.CIDR, Direction: r.Direction, Allow: r.Allow})
	}
	for _, d := range e.DomainRules {
		role.DomainRules = append(role.DomainRules, jailer.DomainRule{Domain: d.Domain, Allow: d.Allow})
	}
	if e.Proxy != nil {
		role.Proxy = &jailer.Proxy{Address: e.Proxy.Address, Required: e.Proxy.Required}
	}
	return role
}

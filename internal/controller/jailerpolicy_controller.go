// Package controller reconciles JailerPolicy objects.
//
// The controller resolves intent and reports it. It does not enforce: that
// happens per-node, in the agent and the engine below it. What it owns is the
// part an operator can see -- how many pods a policy selects, how many are
// actually enrolled, and whether the spec is usable at all.
package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/gen0sec/jailer-operator/api/v1alpha1"
	"github.com/gen0sec/jailer-operator/internal/selector"
	"github.com/gen0sec/jailer-operator/internal/validate"
)

const (
	conditionReady    = "Ready"
	conditionDegraded = "Degraded"
)

// JailerPolicyReconciler keeps a policy's status in step with the pods it
// selects.
type JailerPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=jailer.gen0sec.com,resources=jailerpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=jailer.gen0sec.com,resources=jailerpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods;namespaces,verbs=get;list;watch

func (r *JailerPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var policy v1alpha1.JailerPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		// Deleted between the event and now: nothing to reconcile, and
		// requeuing forever would be noise.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	policy.Status.ObservedGeneration = policy.Generation

	if problems := validate.Spec(policy.Spec); len(problems) > 0 {
		// Reported rather than dropped: a policy the agent cannot apply must
		// not look like one that is in force.
		setCondition(&policy, conditionDegraded, metav1.ConditionTrue, "InvalidSpec",
			summarise(problems))
		setCondition(&policy, conditionReady, metav1.ConditionFalse, "InvalidSpec",
			"the spec has problems that prevent it being applied")
		policy.Status.MatchedPods = 0
		policy.Status.EnrolledPods = 0
		return ctrl.Result{}, r.Status().Update(ctx, &policy)
	}

	matched, err := r.countMatchingPods(ctx, policy.Spec)
	if err != nil {
		setCondition(&policy, conditionDegraded, metav1.ConditionTrue, "SelectorError", err.Error())
		setCondition(&policy, conditionReady, metav1.ConditionFalse, "SelectorError", err.Error())
		if updateErr := r.Status().Update(ctx, &policy); updateErr != nil {
			return ctrl.Result{}, errors.Join(err, updateErr)
		}
		return ctrl.Result{}, err
	}

	policy.Status.MatchedPods = int32(matched)
	setCondition(&policy, conditionDegraded, metav1.ConditionFalse, "SpecAccepted",
		"the spec is usable")
	setCondition(&policy, conditionReady, metav1.ConditionTrue, "SpecAccepted",
		fmt.Sprintf("selects %d pod(s)", matched))

	return ctrl.Result{}, r.Status().Update(ctx, &policy)
}

func (r *JailerPolicyReconciler) countMatchingPods(ctx context.Context, spec v1alpha1.JailerPolicySpec) (int, error) {
	var namespaces corev1.NamespaceList
	if err := r.List(ctx, &namespaces); err != nil {
		return 0, fmt.Errorf("listing namespaces: %w", err)
	}

	count := 0
	for _, ns := range namespaces.Items {
		var pods corev1.PodList
		if err := r.List(ctx, &pods, client.InNamespace(ns.Name)); err != nil {
			return 0, fmt.Errorf("listing pods in %s: %w", ns.Name, err)
		}
		for _, pod := range pods.Items {
			ok, err := selector.Matches(spec, ns.Labels, pod.Labels)
			if err != nil {
				return 0, err
			}
			if ok {
				count++
			}
		}
	}
	return count, nil
}

func summarise(problems []error) string {
	parts := make([]string, 0, len(problems))
	for _, p := range problems {
		parts = append(parts, p.Error())
	}
	return strings.Join(parts, "; ")
}

func setCondition(p *v1alpha1.JailerPolicy, condType string, status metav1.ConditionStatus,
	reason, message string) {
	cond := metav1.Condition{
		Type: condType, Status: status, Reason: reason, Message: message,
		ObservedGeneration: p.Generation,
	}
	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == condType {
			if p.Status.Conditions[i].Status != status {
				cond.LastTransitionTime = metav1.Now()
			} else {
				cond.LastTransitionTime = p.Status.Conditions[i].LastTransitionTime
			}
			p.Status.Conditions[i] = cond
			return
		}
	}
	cond.LastTransitionTime = metav1.Now()
	p.Status.Conditions = append(p.Status.Conditions, cond)
}

// SetupWithManager registers the controller. Pods and namespaces are watched
// because a policy's matched count changes when they do, not only when the
// policy itself is edited.
func (r *JailerPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.JailerPolicy{}).
		Watches(&corev1.Pod{}, r.enqueueAll()).
		Watches(&corev1.Namespace{}, r.enqueueAll()).
		Complete(r)
}

// enqueueAll maps any pod or namespace event onto every policy: a label change
// can add or remove a pod from any selector, so there is no cheaper mapping
// without an index.
func (r *JailerPolicyReconciler) enqueueAll() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, _ client.Object) []reconcile.Request {
		var policies v1alpha1.JailerPolicyList
		if err := r.List(ctx, &policies); err != nil {
			return nil
		}
		reqs := make([]reconcile.Request, 0, len(policies.Items))
		for _, p := range policies.Items {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: client.ObjectKey{Name: p.Name}})
		}
		return reqs
	})
}

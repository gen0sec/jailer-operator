package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gen0sec/jailer-operator/api/v1alpha1"
)

func scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func ns(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func pod(namespace, name string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels,
			UID: types.UID(namespace + "-" + name)},
		Status: corev1.PodStatus{QOSClass: corev1.PodQOSBestEffort, Phase: corev1.PodRunning},
	}
}

func reconcileOnce(t *testing.T, objs ...client.Object) (*v1alpha1.JailerPolicy, error) {
	t.Helper()
	s := scheme(t)
	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&v1alpha1.JailerPolicy{}).Build()
	r := &JailerPolicyReconciler{Client: c, Scheme: s}
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "p"}})
	if err != nil {
		return nil, err
	}
	got := &v1alpha1.JailerPolicy{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: "p"}, got); err != nil {
		t.Fatal(err)
	}
	return got, nil
}

func policy(spec v1alpha1.JailerPolicySpec) *v1alpha1.JailerPolicy {
	p := &v1alpha1.JailerPolicy{ObjectMeta: metav1.ObjectMeta{Name: "p", Generation: 3}, Spec: spec}
	return p
}

func TestStatusCountsTheMatchedPods(t *testing.T) {
	p := policy(v1alpha1.JailerPolicySpec{
		PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}})
	got, err := reconcileOnce(t, p, ns("default", nil),
		pod("default", "web-1", map[string]string{"app": "web"}),
		pod("default", "web-2", map[string]string{"app": "web"}),
		pod("default", "db-1", map[string]string{"app": "db"}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Status.MatchedPods != 2 {
		t.Errorf("MatchedPods = %d, want 2", got.Status.MatchedPods)
	}
}

// A pod is only counted as enrolled once the agent has marked it, which it
// does after the daemon accepts. Counting selected pods as enrolled would
// report a policy in force before anything reached a map.
func TestOnlyMarkedPodsCountAsEnrolled(t *testing.T) {
	p := policy(v1alpha1.JailerPolicySpec{
		PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}})
	marked := pod("default", "web-1", map[string]string{"app": "web"})
	marked.Annotations = map[string]string{v1alpha1.AnnotationEnrolledRole: "7"}

	got, err := reconcileOnce(t, p, ns("default", nil), marked,
		pod("default", "web-2", map[string]string{"app": "web"}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Status.MatchedPods != 2 {
		t.Errorf("MatchedPods = %d, want 2", got.Status.MatchedPods)
	}
	if got.Status.EnrolledPods != 1 {
		t.Errorf("EnrolledPods = %d, want 1 (only the marked pod)", got.Status.EnrolledPods)
	}
}

func TestStatusRecordsTheObservedGeneration(t *testing.T) {
	got, err := reconcileOnce(t, policy(v1alpha1.JailerPolicySpec{}), ns("default", nil))
	if err != nil {
		t.Fatal(err)
	}
	if got.Status.ObservedGeneration != 3 {
		t.Errorf("ObservedGeneration = %d, want 3", got.Status.ObservedGeneration)
	}
}

func TestTheNamespaceSelectorIsHonoured(t *testing.T) {
	p := policy(v1alpha1.JailerPolicySpec{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "prod"}}})
	got, err := reconcileOnce(t, p,
		ns("prod", map[string]string{"tier": "prod"}), ns("dev", map[string]string{"tier": "dev"}),
		pod("prod", "a", nil), pod("dev", "b", nil))
	if err != nil {
		t.Fatal(err)
	}
	if got.Status.MatchedPods != 1 {
		t.Errorf("MatchedPods = %d, want 1 (only the prod namespace)", got.Status.MatchedPods)
	}
}

// An invalid spec must be visible on the object. Reconciling it silently
// would leave an operator believing a policy is in force.
func TestAnInvalidSpecIsReportedAsDegraded(t *testing.T) {
	p := policy(v1alpha1.JailerPolicySpec{
		IPRules: []v1alpha1.IPRule{{CIDR: "nonsense", Direction: "connect"}}})
	got, err := reconcileOnce(t, p, ns("default", nil))
	if err != nil {
		t.Fatal(err)
	}
	cond := meta(got, "Degraded")
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("want Degraded=True, got %+v", got.Status.Conditions)
	}
	if cond.Message == "" {
		t.Error("the condition should say what is wrong")
	}
}

func TestAValidSpecIsReady(t *testing.T) {
	got, err := reconcileOnce(t, policy(v1alpha1.JailerPolicySpec{}), ns("default", nil))
	if err != nil {
		t.Fatal(err)
	}
	cond := meta(got, "Ready")
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("want Ready=True, got %+v", got.Status.Conditions)
	}
}

// A policy that has been deleted must not fail the reconcile loop.
func TestAMissingPolicyIsNotAnError(t *testing.T) {
	s := scheme(t)
	c := fake.NewClientBuilder().WithScheme(s).WithStatusSubresource(&v1alpha1.JailerPolicy{}).Build()
	r := &JailerPolicyReconciler{Client: c, Scheme: s}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "gone"}}); err != nil {
		t.Errorf("want no error for a deleted policy, got %v", err)
	}
}

func meta(p *v1alpha1.JailerPolicy, t string) *metav1.Condition {
	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == t {
			return &p.Status.Conditions[i]
		}
	}
	return nil
}

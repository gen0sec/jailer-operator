package enroll

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gen0sec/jailer-operator/api/v1alpha1"
	"github.com/gen0sec/jailer-operator/internal/cgroup"
	"github.com/gen0sec/jailer-operator/internal/roleid"
)

func webPolicy() v1alpha1.JailerPolicy {
	p := v1alpha1.JailerPolicy{Spec: v1alpha1.JailerPolicySpec{
		PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		IPRules:     []v1alpha1.IPRule{{CIDR: "10.0.0.0/8", Direction: "connect"}},
	}}
	p.Name = "web"
	return p
}

func aPod() Pod {
	return Pod{
		UID: "55989c3a-8ea8-48d7-9e1e-3c078902d007", Namespace: "default",
		Name: "victim", QoSClass: "BestEffort", Labels: map[string]string{"app": "web"},
	}
}

func plan(t *testing.T, pod Pod, policies []v1alpha1.JailerPolicy) (*Enrollment, error) {
	t.Helper()
	return Plan(pod, nil, policies, "/sys/fs/cgroup", cgroup.Systemd, roleid.New(roleid.DefaultCapacity))
}

func TestAMatchingPolicyProducesThePodSliceEnrollment(t *testing.T) {
	got, err := plan(t, aPod(), []v1alpha1.JailerPolicy{webPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("a matching policy must produce an enrollment")
	}
	want := "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/" +
		"kubepods-besteffort-pod55989c3a_8ea8_48d7_9e1e_3c078902d007.slice"
	if got.CgroupPath != want {
		t.Errorf("\n got: %s\nwant: %s", got.CgroupPath, want)
	}
	if got.RoleID == 0 {
		t.Error("role 0 is what an unenrolled task carries")
	}
	if got.PodID == 0 {
		t.Error("pod id 0 means unenrolled to the engine")
	}
}

// No policy means the pod is left alone. Enrolling it with an empty role
// would look like enforcement while enforcing nothing.
func TestNoMatchingPolicyMeansNoEnrollment(t *testing.T) {
	pod := aPod()
	pod.Labels = map[string]string{"app": "db"}
	got, err := plan(t, pod, []v1alpha1.JailerPolicy{webPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("want no enrollment, got %+v", got)
	}
}

// A pod that has not been scheduled has no QoS class yet. Guessing one would
// build a path that does not exist and enroll nothing.
func TestAPodWithoutAQoSClassIsAnError(t *testing.T) {
	pod := aPod()
	pod.QoSClass = ""
	if _, err := plan(t, pod, []v1alpha1.JailerPolicy{webPolicy()}); err == nil {
		t.Error("want an error rather than a guessed path")
	}
}

func TestAPodWithoutAUIDIsAnError(t *testing.T) {
	pod := aPod()
	pod.UID = ""
	if _, err := plan(t, pod, []v1alpha1.JailerPolicy{webPolicy()}); err == nil {
		t.Error("want an error: the path would name the QoS slice and cover every pod in it")
	}
}

// The pod id identifies the pod to the engine, so two pods must not share one.
func TestPodIDsDifferBetweenPods(t *testing.T) {
	a, _ := plan(t, aPod(), []v1alpha1.JailerPolicy{webPolicy()})
	other := aPod()
	other.UID = "11111111-2222-3333-4444-555555555555"
	b, _ := plan(t, other, []v1alpha1.JailerPolicy{webPolicy()})
	if a.PodID == b.PodID {
		t.Error("distinct pods share a pod id")
	}
}

func TestPodIDIsStableForTheSamePod(t *testing.T) {
	a, _ := plan(t, aPod(), []v1alpha1.JailerPolicy{webPolicy()})
	b, _ := plan(t, aPod(), []v1alpha1.JailerPolicy{webPolicy()})
	if a.PodID != b.PodID {
		t.Error("pod id churned for the same pod")
	}
}

// Two pods under the same policy share a role: the role is the policy, not
// the pod. Otherwise 1024 roles would be exhausted by a few hundred pods.
func TestPodsUnderTheSamePolicyShareARole(t *testing.T) {
	ids := roleid.New(roleid.DefaultCapacity)
	one := aPod()
	two := aPod()
	two.UID = "99999999-8888-7777-6666-555555555555"
	a, _ := Plan(one, nil, []v1alpha1.JailerPolicy{webPolicy()}, "/sys/fs/cgroup", cgroup.Systemd, ids)
	b, _ := Plan(two, nil, []v1alpha1.JailerPolicy{webPolicy()}, "/sys/fs/cgroup", cgroup.Systemd, ids)
	if a.RoleID != b.RoleID {
		t.Errorf("same policy gave role %d and %d", a.RoleID, b.RoleID)
	}
}

func TestConflictingPoliciesSurfaceTheMergeError(t *testing.T) {
	a := webPolicy()
	a.Spec.Proxy = &v1alpha1.ProxyConfig{Address: "10.0.0.1:3128", Required: true}
	b := webPolicy()
	b.Name = "web-2"
	b.Spec.Proxy = &v1alpha1.ProxyConfig{Address: "10.0.0.2:3128", Required: true}

	_, err := plan(t, aPod(), []v1alpha1.JailerPolicy{a, b})
	if err == nil || !strings.Contains(err.Error(), "proxy") {
		t.Errorf("want the proxy conflict reported, got %v", err)
	}
}

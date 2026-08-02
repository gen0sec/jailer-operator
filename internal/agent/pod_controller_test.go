package agent

import (
	"context"
	"errors"
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
	"github.com/gen0sec/jailer-operator/internal/cgroup"
	"github.com/gen0sec/jailer-operator/internal/jailer"
	"github.com/gen0sec/jailer-operator/internal/roleid"
)

type call struct {
	path   string
	podID  uint64
	roleID uint32
}

type fakeJailer struct {
	enrolled []call
	defined  []jailer.Role
	removed  []string
	err      error
}

func (f *fakeJailer) DefineRole(_ context.Context, role jailer.Role) error {
	if f.err != nil {
		return f.err
	}
	f.defined = append(f.defined, role)
	return nil
}

func (f *fakeJailer) EnrollCgroup(_ context.Context, path string, podID uint64, roleID uint32) error {
	if f.err != nil {
		return f.err
	}
	f.enrolled = append(f.enrolled, call{path, podID, roleID})
	return nil
}

func (f *fakeJailer) RemoveCgroup(_ context.Context, path string) error {
	f.removed = append(f.removed, path)
	return nil
}

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

func webPolicy() *v1alpha1.JailerPolicy {
	p := &v1alpha1.JailerPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "web"},
		Spec: v1alpha1.JailerPolicySpec{
			PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			IPRules:     []v1alpha1.IPRule{{CIDR: "10.0.0.0/8", Direction: "connect"}},
		}}
	return p
}

func aPod(node string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "victim", Labels: labels,
			UID: types.UID("55989c3a-8ea8-48d7-9e1e-3c078902d007")},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{QOSClass: corev1.PodQOSBestEffort, Phase: corev1.PodRunning},
	}
}

func run(t *testing.T, j *fakeJailer, objs ...client.Object) (*corev1.Pod, error) {
	t.Helper()
	s := scheme(t)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	r := &PodReconciler{Client: c, Scheme: s, NodeName: "node-a",
		CgroupRoot: "/sys/fs/cgroup", Driver: cgroup.Systemd, Jailer: j,
		IDs: roleid.New(roleid.DefaultCapacity)}
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "victim"}})
	if err != nil {
		return nil, err
	}
	got := &corev1.Pod{}
	if getErr := c.Get(context.Background(),
		types.NamespacedName{Namespace: "default", Name: "victim"}, got); getErr != nil {
		return nil, err
	}
	return got, err
}

func TestAMatchingPodIsEnrolledAtItsPodSlice(t *testing.T) {
	j := &fakeJailer{}
	_, err := run(t, j, webPolicy(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		aPod("node-a", map[string]string{"app": "web"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(j.enrolled) != 1 {
		t.Fatalf("want one enrollment, got %v", j.enrolled)
	}
	want := "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/" +
		"kubepods-besteffort-pod55989c3a_8ea8_48d7_9e1e_3c078902d007.slice"
	if j.enrolled[0].path != want {
		t.Errorf("\n got: %s\nwant: %s", j.enrolled[0].path, want)
	}
}

// The marker is what the controller counts, so it must be written only after
// the daemon has accepted.
func TestThePodIsMarkedAfterTheDaemonAccepts(t *testing.T) {
	j := &fakeJailer{}
	got, err := run(t, j, webPolicy(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		aPod("node-a", map[string]string{"app": "web"}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Annotations[v1alpha1.AnnotationEnrolledRole] == "" {
		t.Error("the pod was not marked, so the controller will never count it")
	}
}

func TestAPodIsNotMarkedWhenTheDaemonRefuses(t *testing.T) {
	j := &fakeJailer{err: errors.New("role table full")}
	got, err := run(t, j, webPolicy(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		aPod("node-a", map[string]string{"app": "web"}))
	if err == nil {
		t.Fatal("a refusal must surface so the agent retries")
	}
	if got != nil && got.Annotations[v1alpha1.AnnotationEnrolledRole] != "" {
		t.Error("a refused pod must not be marked as enrolled")
	}
}

// Each agent owns one node. Enrolling a pod scheduled elsewhere would write a
// cgroup path that does not exist on this host.
func TestAPodOnAnotherNodeIsIgnored(t *testing.T) {
	j := &fakeJailer{}
	_, err := run(t, j, webPolicy(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		aPod("node-b", map[string]string{"app": "web"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(j.enrolled) != 0 {
		t.Errorf("enrolled a pod belonging to another node: %v", j.enrolled)
	}
}

func TestAPodMatchingNoPolicyIsNotEnrolled(t *testing.T) {
	j := &fakeJailer{}
	got, err := run(t, j, webPolicy(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		aPod("node-a", map[string]string{"app": "db"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(j.enrolled) != 0 {
		t.Errorf("enrolled an unmatched pod: %v", j.enrolled)
	}
	if got.Annotations[v1alpha1.AnnotationEnrolledRole] != "" {
		t.Error("an unmatched pod must not look enrolled")
	}
}

// A pod that has not been scheduled has no QoS class, so its path is not yet
// knowable. That is a wait, not a failure.
func TestAnUnscheduledPodIsSkippedWithoutError(t *testing.T) {
	j := &fakeJailer{}
	pod := aPod("node-a", map[string]string{"app": "web"})
	pod.Status.QOSClass = ""
	if _, err := run(t, j, webPolicy(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}, pod); err != nil {
		t.Errorf("want no error for a pod that is not ready to enroll, got %v", err)
	}
	if len(j.enrolled) != 0 {
		t.Error("nothing should have been enrolled")
	}
}

func TestADeletedPodIsNotAnError(t *testing.T) {
	j := &fakeJailer{}
	s := scheme(t)
	c := fake.NewClientBuilder().WithScheme(s).Build()
	r := &PodReconciler{Client: c, Scheme: s, NodeName: "node-a",
		CgroupRoot: "/sys/fs/cgroup", Driver: cgroup.Systemd, Jailer: j,
		IDs: roleid.New(roleid.DefaultCapacity)}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "gone"}}); err != nil {
		t.Errorf("want no error for a deleted pod, got %v", err)
	}
}

// Enrolling against a role the daemon has never been told about is refused as
// unknown, so the role has to be defined first and must carry the rules.
func TestTheRoleIsDefinedBeforeTheEnrollment(t *testing.T) {
	j := &fakeJailer{}
	if _, err := run(t, j, webPolicy(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		aPod("node-a", map[string]string{"app": "web"})); err != nil {
		t.Fatal(err)
	}
	if len(j.defined) != 1 {
		t.Fatalf("want the role defined, got %v", j.defined)
	}
	if len(j.enrolled) != 1 {
		t.Fatalf("want one enrollment, got %v", j.enrolled)
	}
	if j.defined[0].ID != j.enrolled[0].roleID {
		t.Errorf("defined role %d but enrolled %d", j.defined[0].ID, j.enrolled[0].roleID)
	}
	if len(j.defined[0].IPRules) != 1 {
		t.Errorf("the role reached the daemon without its rules: %+v", j.defined[0])
	}
}

// A pod stops matching when a policy is edited, a label changes, or an opt-in
// annotation is removed. If nothing undoes the enrollment the pod stays jailed
// in the kernel under a role no policy grants it -- enforcement that no longer
// appears anywhere in the API.
func TestAPodThatStopsMatchingIsUnenrolled(t *testing.T) {
	j := &fakeJailer{}
	pod := aPod("node-a", map[string]string{"app": "db"}) // no longer selected
	pod.Annotations = map[string]string{v1alpha1.AnnotationEnrolledRole: "734"}

	got, err := run(t, j, webPolicy(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}, pod)
	if err != nil {
		t.Fatal(err)
	}
	if len(j.removed) != 1 {
		t.Fatalf("want the enrollment removed, got %v", j.removed)
	}
	want := "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/" +
		"kubepods-besteffort-pod55989c3a_8ea8_48d7_9e1e_3c078902d007.slice"
	if j.removed[0] != want {
		t.Errorf("\n got: %s\nwant: %s", j.removed[0], want)
	}
	if got.Annotations[v1alpha1.AnnotationEnrolledRole] != "" {
		t.Error("the marker must go too, or the pod still counts as enrolled")
	}
}

// A pod that never matched has nothing to undo, and asking the daemon to
// remove an enrollment it does not have would be noise on every reconcile.
func TestAnUnmarkedPodIsNotUnenrolled(t *testing.T) {
	j := &fakeJailer{}
	if _, err := run(t, j, webPolicy(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		aPod("node-a", map[string]string{"app": "db"})); err != nil {
		t.Fatal(err)
	}
	if len(j.removed) != 0 {
		t.Errorf("nothing was enrolled, so nothing should be removed: %v", j.removed)
	}
}

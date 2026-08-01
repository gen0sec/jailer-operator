package cgroup

import (
	"strings"
	"testing"
)

// The expectations below are taken from a running k3s node (v1.36.2,
// containerd 2.3.2), not from documentation.
func TestPodSlice(t *testing.T) {
	const root = "/sys/fs/cgroup"
	const uid = "55989c3a-8ea8-48d7-9e1e-3c078902d007"

	for _, tc := range []struct {
		name   string
		driver Driver
		qos    string
		want   string
	}{{
		name:   "systemd besteffort",
		driver: Systemd, qos: "BestEffort",
		// Observed verbatim on the node.
		want: "/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/" +
			"kubepods-besteffort-pod55989c3a_8ea8_48d7_9e1e_3c078902d007.slice",
	}, {
		name:   "systemd burstable",
		driver: Systemd, qos: "Burstable",
		want: "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/" +
			"kubepods-burstable-pod55989c3a_8ea8_48d7_9e1e_3c078902d007.slice",
	}, {
		// Guaranteed pods have no QoS level: the kubelet puts them directly
		// under kubepods. Getting this wrong yields a path that never exists
		// and an enrollment that silently enforces nothing.
		name:   "systemd guaranteed has no qos level",
		driver: Systemd, qos: "Guaranteed",
		want: "/sys/fs/cgroup/kubepods.slice/" +
			"kubepods-pod55989c3a_8ea8_48d7_9e1e_3c078902d007.slice",
	}, {
		name:   "cgroupfs besteffort",
		driver: Cgroupfs, qos: "BestEffort",
		want: "/sys/fs/cgroup/kubepods/besteffort/pod55989c3a-8ea8-48d7-9e1e-3c078902d007",
	}, {
		name:   "cgroupfs guaranteed has no qos level",
		driver: Cgroupfs, qos: "Guaranteed",
		want: "/sys/fs/cgroup/kubepods/pod55989c3a-8ea8-48d7-9e1e-3c078902d007",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PodSlice(root, tc.driver, tc.qos, uid)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// systemd escapes dashes in unit names, so the pod UID's dashes become
// underscores. A path built with dashes does not exist.
func TestSystemdUIDIsUnderscored(t *testing.T) {
	got, err := PodSlice("/sys/fs/cgroup", Systemd, "BestEffort", "a-b-c")
	if err != nil {
		t.Fatal(err)
	}
	if want := "kubepods-besteffort-poda_b_c.slice"; !strings.HasSuffix(got, want) {
		t.Errorf("got %s, want it to end with %s", got, want)
	}
}

func TestUnknownDriverIsRejected(t *testing.T) {
	if _, err := PodSlice("/sys/fs/cgroup", Driver("rkt"), "BestEffort", "x"); err == nil {
		t.Error("an unknown cgroup driver must be an error, not a wrong path")
	}
}

func TestEmptyUIDIsRejected(t *testing.T) {
	if _, err := PodSlice("/sys/fs/cgroup", Systemd, "BestEffort", ""); err == nil {
		t.Error("an empty pod UID would enroll the QoS slice, covering every pod in that class")
	}
}

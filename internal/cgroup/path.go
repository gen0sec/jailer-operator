// Package cgroup derives the cgroup path a pod's containers live under.
//
// The path is what jailer enrolls, and an enrollment covers a cgroup and
// everything beneath it, so naming the pod slice covers every container in the
// pod -- including replacements created by a restart, whose own scope name
// carries a container id that changes each time.
package cgroup

import (
	"fmt"
	"strings"
)

// Driver is the kubelet's cgroup driver. The two produce different layouts.
type Driver string

const (
	Systemd  Driver = "systemd"
	Cgroupfs Driver = "cgroupfs"
)

// PodSlice returns the absolute cgroup path for a pod.
//
// qosClass is the value of pod.status.qosClass. Guaranteed pods are a special
// case: the kubelet places them directly under kubepods with no QoS level.
func PodSlice(root string, driver Driver, qosClass string, podUID string) (string, error) {
	if podUID == "" {
		return "", fmt.Errorf("empty pod UID: the path would name the QoS slice and cover every pod in that class")
	}
	qos := strings.ToLower(qosClass)
	switch qos {
	case "guaranteed", "burstable", "besteffort":
	default:
		return "", fmt.Errorf("unknown QoS class %q", qosClass)
	}

	switch driver {
	case Systemd:
		// systemd escapes dashes in unit names, so the UID is underscored.
		uid := strings.ReplaceAll(podUID, "-", "_")
		if qos == "guaranteed" {
			return fmt.Sprintf("%s/kubepods.slice/kubepods-pod%s.slice", root, uid), nil
		}
		return fmt.Sprintf("%s/kubepods.slice/kubepods-%s.slice/kubepods-%s-pod%s.slice",
			root, qos, qos, uid), nil
	case Cgroupfs:
		if qos == "guaranteed" {
			return fmt.Sprintf("%s/kubepods/pod%s", root, podUID), nil
		}
		return fmt.Sprintf("%s/kubepods/%s/pod%s", root, qos, podUID), nil
	default:
		return "", fmt.Errorf("unknown cgroup driver %q", driver)
	}
}

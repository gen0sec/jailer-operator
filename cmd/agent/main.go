// Command agent enrolls the pods scheduled to this node with the local
// bpfjailer daemon.
//
// It runs as a DaemonSet because enrollment is per-node: a cgroup path only
// exists on the host its pod runs on.
package main

import (
	"flag"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/gen0sec/jailer-operator/api/v1alpha1"
	"github.com/gen0sec/jailer-operator/internal/agent"
	"github.com/gen0sec/jailer-operator/internal/cgroup"
	"github.com/gen0sec/jailer-operator/internal/jailer"
	"github.com/gen0sec/jailer-operator/internal/roleid"
)

func main() {
	var socketPath, cgroupRoot, driver, probeAddr, metricsAddr string
	flag.StringVar(&socketPath, "jailer-socket", jailer.DefaultSocketPath,
		"the bpfjailer daemon's enrollment socket")
	flag.StringVar(&cgroupRoot, "cgroup-root", "/sys/fs/cgroup", "cgroup2 mount point")
	flag.StringVar(&driver, "cgroup-driver", string(cgroup.Systemd),
		"kubelet cgroup driver: systemd or cgroupfs. The two produce different paths, "+
			"and a wrong one enrolls a cgroup that does not exist")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "readiness and liveness endpoint")
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "metrics endpoint; 0 disables it")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("setup")

	// Supplied by the downward API. Without it the agent cannot tell which
	// pods are its own, and enrolling another node's pod would name a cgroup
	// that does not exist here.
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Error(nil, "NODE_NAME is not set")
		os.Exit(1)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		log.Error(err, "registering core types")
		os.Exit(1)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		log.Error(err, "registering JailerPolicy")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		// Watch only this node's pods: on a large cluster caching every pod on
		// every node would cost far more than it can ever use.
		Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
			&corev1.Pod{}: {Field: fields.OneTermEqualSelector("spec.nodeName", nodeName)},
		}},
	})
	if err != nil {
		log.Error(err, "starting manager")
		os.Exit(1)
	}

	if err := (&agent.PodReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		NodeName:   nodeName,
		CgroupRoot: cgroupRoot,
		Driver:     cgroup.Driver(driver),
		Jailer:     jailer.New(socketPath),
		IDs:        roleid.New(roleid.DefaultCapacity),
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "registering pod controller")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Error(err, "adding health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Error(err, "adding ready check")
		os.Exit(1)
	}

	log.Info("starting", "node", nodeName, "driver", driver, "socket", socketPath)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "agent exited")
		os.Exit(1)
	}
}

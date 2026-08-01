# jailer-operator

Kubernetes policy handling for [jailer](https://github.com/gen0sec/jailer), an
eBPF/LSM mandatory access control engine.

jailer enforces per-cgroup: a policy names a cgroup, and the enrollment covers
that cgroup and everything beneath it. This operator turns cluster-wide,
label-selected intent into those per-node enrollments.

## Status

Early. The pure pieces — policy merging and pod-to-cgroup derivation — are
implemented and tested. The controller and node agent are not yet written.

## Architecture

Enforcement is per-node, so a cluster-scoped controller alone cannot do the
job; there are two components.

| layer | responsibility |
|---|---|
| `JailerPolicy` CRD | intent: selectors plus rules, cluster-scoped |
| controller | resolve selectors, merge matching policies, allocate stable role ids, report status |
| node agent (DaemonSet) | derive a pod's cgroup path, enroll it through the jailer daemon socket |
| jailer daemon | maps and enforcement |

## Design decisions

**Matching policies merge; none is ignored.** A pod can match several
selectors, but jailer gives a cgroup exactly one role. Rules from every
matching policy are concatenated, and flags are ANDed so the most restrictive
policy wins. The alternative — ranking policies and applying only the winner —
would mean a policy that appears applied enforces nothing, which is the failure
mode this project is meant to eliminate rather than reproduce.

**Flags carry no default.** A flag no policy sets stays unset. Defaulting an
unset `allowX` to true would grant a capability nobody asked for.

**Conflicting proxies are an error, not a choice.** Egress can be forced
through one proxy. If two policies name different ones, the merge fails and
says so, because silently picking one sends traffic somewhere the operator did
not ask for.

**The merge is order-independent.** Policies are sorted before merging and
rules are canonically ordered, so the fingerprint that drives role-id
allocation does not change because an informer delivered objects in a different
order. Rule order carries no meaning on the jailer side — every rule kind lands
in a hash map — so canonical ordering is safe.

**Enroll the pod slice, not the container scope.** A container's cgroup name
embeds a container id that changes on every restart, so an enrollment naming it
lapses silently on any rollout. The pod slice is derivable from the pod UID and
QoS class as soon as the pod is scheduled, before its containers exist.

**A node-wide floor belongs underneath this.** Even with an operator, a pod can
start before its enrollment lands. jailer can enroll `kubepods.slice`
statically at boot, which covers every pod without any discovery; the operator
then refines upward. Without that floor every pod has an unjailed window.

## Development

    go test ./...

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Flags are the coarse capabilities a role permits. They are permissive by
// name: allow_x=false is a restriction. Merging ANDs them, so the most
// restrictive matching policy wins.
// Every flag defaults to true, and the API server fills that in, so the value
// that will be enforced is visible in the stored object rather than decided
// later where nobody can see it.
//
// A permissive default cannot grant anything by accident: merging ANDs these,
// so any policy that sets false still wins. The default only decides what
// happens when no policy expressed an opinion, and "nobody withheld this"
// should not mean "withhold it". Setting false is how a dimension becomes
// default-deny, and it pairs with allow rules to make an allow-list.
type Flags struct {
	// +kubebuilder:default=true
	// +optional
	AllowFileAccess *bool `json:"allowFileAccess,omitempty"`
	// +kubebuilder:default=true
	// +optional
	AllowNetwork *bool `json:"allowNetwork,omitempty"`
	// +kubebuilder:default=true
	// +optional
	AllowExec *bool `json:"allowExec,omitempty"`
	// +kubebuilder:default=true
	// +optional
	AllowSetuid *bool `json:"allowSetuid,omitempty"`
	// runc opens /proc/<pid>/ns/* while starting a container, which the kernel
	// gates behind ptrace_may_access, so withholding this from a role that
	// covers a pod slice stops its containers starting at all.
	// +kubebuilder:default=true
	// +optional
	AllowPtrace *bool `json:"allowPtrace,omitempty"`
}

type FilePathRule struct {
	// Pattern is an absolute path, optionally with * standing for one
	// component. Matching walks components from the root, so a relative
	// pattern can never match.
	// +kubebuilder:validation:Pattern=`^/.*`
	// +kubebuilder:validation:MinLength=1
	Pattern string `json:"pattern"`
	Allow   bool   `json:"allow"`
}

type IPRule struct {
	// +kubebuilder:validation:MinLength=1
	CIDR string `json:"cidr"`
	// +kubebuilder:validation:Enum=connect;bind
	Direction string `json:"direction"`
	Allow     bool   `json:"allow"`
}

type DomainRule struct {
	// +kubebuilder:validation:MinLength=1
	Domain string `json:"domain"`
	Allow  bool   `json:"allow"`
}

type ProxyConfig struct {
	// Address is an IPv4 literal and port. Nothing resolves this, and the
	// engine compares a 32-bit address, so a hostname would never match.
	// +kubebuilder:validation:Pattern=`^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$`
	Address  string `json:"address"`
	Required bool   `json:"required"`
}

type JailerPolicySpec struct {
	// NamespaceSelector and PodSelector together choose the pods this policy
	// applies to. A nil NamespaceSelector means every namespace.
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	PodSelector       *metav1.LabelSelector `json:"podSelector,omitempty"`

	// NamespaceAnnotationSelector and PodAnnotationSelector match annotations
	// instead of labels. They reuse the label selector shape, so
	// matchExpressions works exactly as it does above rather than being a
	// second dialect.
	//
	// Kubernetes has no annotation index, so unlike labels these can never be
	// pushed down to the API server. That costs nothing here -- the controller
	// already evaluates every selector itself, and the agent already narrows
	// to its own node by field selector -- but it does rule out server-side
	// filtering as a later optimisation.
	// +optional
	NamespaceAnnotationSelector *metav1.LabelSelector `json:"namespaceAnnotationSelector,omitempty"`
	// +optional
	PodAnnotationSelector *metav1.LabelSelector `json:"podAnnotationSelector,omitempty"`

	// RequireOptIn narrows the policy to pods carrying
	// jailer.gen0sec.com/opt-in: "true".
	//
	// This is the ergonomic form of a PodAnnotationSelector on that key: one
	// well-known name, so a staged rollout does not depend on spelling an
	// annotation identically in every policy. It only ever narrows -- a pod
	// that opts in still has to satisfy the other selectors.
	// +optional
	RequireOptIn *bool `json:"requireOptIn,omitempty"`

	// Defaulted as an object so the per-flag defaults below actually apply:
	// nested defaults only fire when the parent exists, so a spec that omits
	// flags entirely would otherwise store nothing and leave the effective
	// value invisible.
	// +kubebuilder:default={}
	// +optional
	Flags       Flags          `json:"flags,omitempty"`
	FilePaths   []FilePathRule `json:"filePaths,omitempty"`
	IPRules     []IPRule       `json:"ipRules,omitempty"`
	DomainRules []DomainRule   `json:"domainRules,omitempty"`
	Proxy       *ProxyConfig   `json:"proxy,omitempty"`
}

// JailerPolicyStatus reports what the policy is actually doing.
//
// Every defect found in the enforcement engine so far was silent: policy
// present, nothing enforced. Reporting how many pods a policy matched and how
// many are actually enrolled is what makes that difference visible.
type JailerPolicyStatus struct {
	// ObservedGeneration is the .metadata.generation this status reflects.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// MatchedPods is how many pods the selectors chose.
	// +optional
	MatchedPods int32 `json:"matchedPods"`

	// EnrolledPods is how many of those are enrolled on their node. A gap
	// between this and MatchedPods is unenforced policy.
	// +optional
	EnrolledPods int32 `json:"enrolledPods"`

	// Conditions carries Ready, and Degraded when a spec is rejected or a
	// node cannot enroll.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// JailerPolicy is cluster-scoped: it expresses intent across namespaces.
//
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=jp
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Matched",type=integer,JSONPath=`.status.matchedPods`
// +kubebuilder:printcolumn:name="Enrolled",type=integer,JSONPath=`.status.enrolledPods`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type JailerPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   JailerPolicySpec   `json:"spec,omitempty"`
	Status JailerPolicyStatus `json:"status,omitempty"`
}

// JailerPolicyList contains a list of JailerPolicy.
//
// +kubebuilder:object:root=true
type JailerPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []JailerPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&JailerPolicy{}, &JailerPolicyList{})
}

// AnnotationEnrolledRole is written on a pod by the node agent once the
// jailer daemon has accepted its enrollment, and carries the role id.
//
// It is what makes the difference between selected and enforced visible: the
// controller counts matched pods carrying it, so a gap between MatchedPods and
// EnrolledPods is policy that is not in force. Without a marker written after
// the daemon accepts, a policy would look applied the moment it was created.
const AnnotationEnrolledRole = "jailer.gen0sec.com/enrolled-role"

// AnnotationOptIn marks a pod as willing to be governed by policies that set
// RequireOptIn. Only the exact value "true" counts: anything else, including
// an empty value, is not an opt-in.
const AnnotationOptIn = "jailer.gen0sec.com/opt-in"

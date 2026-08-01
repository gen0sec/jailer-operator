package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Flags are the coarse capabilities a role permits. They are permissive by
// name: allow_x=false is a restriction. Merging ANDs them, so the most
// restrictive matching policy wins.
type Flags struct {
	AllowFileAccess *bool `json:"allowFileAccess,omitempty"`
	AllowNetwork    *bool `json:"allowNetwork,omitempty"`
	AllowExec       *bool `json:"allowExec,omitempty"`
	AllowSetuid     *bool `json:"allowSetuid,omitempty"`
	AllowPtrace     *bool `json:"allowPtrace,omitempty"`
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

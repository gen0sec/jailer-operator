// Package v1alpha1 contains the JailerPolicy API.
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
	Pattern string `json:"pattern"`
	Allow   bool   `json:"allow"`
}

type IPRule struct {
	CIDR      string `json:"cidr"`
	Direction string `json:"direction"`
	Allow     bool   `json:"allow"`
}

type DomainRule struct {
	Domain string `json:"domain"`
	Allow  bool   `json:"allow"`
}

type ProxyConfig struct {
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

// JailerPolicy is cluster-scoped: it expresses intent across namespaces.
type JailerPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              JailerPolicySpec `json:"spec,omitempty"`
}

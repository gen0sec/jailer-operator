// Package v1alpha1 contains the JailerPolicy API.
//
// +kubebuilder:object:generate=true
// +groupName=jailer.gen0sec.com
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the group and version for this API.
	GroupVersion = schema.GroupVersion{Group: "jailer.gen0sec.com", Version: "v1alpha1"}

	// SchemeBuilder registers these types with a scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds these types to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

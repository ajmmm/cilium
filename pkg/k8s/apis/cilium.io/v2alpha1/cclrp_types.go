// This file was not reviewed by a human before submission
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium,ciliumpolicy},singular="ciliumclusterwidelocalredirectpolicy",path="ciliumclusterwidelocalredirectpolicies",scope="Cluster",shortName={cclrp}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
// +kubebuilder:subresource:status
// +kubebuilder:object:root=true
// +kubebuilder:storageversion

// CiliumClusterwideLocalRedirectPolicy describes cluster-wide traffic that
// should be redirected to selected node-local pods.
type CiliumClusterwideLocalRedirectPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the desired behavior of the cluster-wide local redirect policy.
	//
	// +kubebuilder:validation:Required
	Spec CiliumClusterwideLocalRedirectPolicySpec `json:"spec"`

	// Status reports policy acceptance and node-local reconciliation errors.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status CiliumClusterwideLocalRedirectPolicyStatus `json:"status,omitempty"`
}

// CiliumClusterwideLocalRedirectPolicyList contains CCLRP objects.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false
type CiliumClusterwideLocalRedirectPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CiliumClusterwideLocalRedirectPolicy `json:"items"`
}

// CiliumClusterwideLocalRedirectPolicySpec defines a local redirect.
//
// +kubebuilder:validation:XValidation:rule="has(self.addressMatcher) != has(self.serviceMatcher)",message="exactly one of addressMatcher or serviceMatcher must be specified"
type CiliumClusterwideLocalRedirectPolicySpec struct {
	// AddressMatcher matches traffic to one link-local IP address.
	//
	// +kubebuilder:validation:Optional
	AddressMatcher *CiliumClusterwideLocalRedirectPolicyAddressMatcher `json:"addressMatcher,omitempty"`

	// ServiceMatcher matches traffic to a Kubernetes Service.
	//
	// +kubebuilder:validation:Optional
	ServiceMatcher *CiliumClusterwideLocalRedirectPolicyServiceMatcher `json:"serviceMatcher,omitempty"`

	// BackendNamespace limits local endpoint selection to this namespace.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	BackendNamespace string `json:"backendNamespace"`

	// LocalEndpointSelector selects pods in BackendNamespace that can receive
	// redirected traffic.
	//
	// +kubebuilder:validation:Required
	LocalEndpointSelector slim_metav1.LabelSelector `json:"localEndpointSelector"`

	// Ports contains explicit frontend-to-backend port mappings.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Ports []CiliumClusterwideLocalRedirectPolicyPort `json:"ports"`
}

// CiliumClusterwideLocalRedirectPolicyAddressMatcher matches one IP address.
type CiliumClusterwideLocalRedirectPolicyAddressMatcher struct {
	// IP is the link-local destination IP address to match.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=ip
	IP string `json:"ip"`
}

// CiliumClusterwideLocalRedirectPolicyServiceMatcher identifies a Service.
type CiliumClusterwideLocalRedirectPolicyServiceMatcher struct {
	// Namespace is the namespace of the destination Service.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`

	// ServiceName is the name of the destination Service.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	ServiceName string `json:"serviceName"`
}

// CiliumClusterwideLocalRedirectPolicyPort maps a frontend port to a backend
// target port for one transport protocol.
type CiliumClusterwideLocalRedirectPolicyPort struct {
	// Port is the frontend destination port.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`

	// TargetPort is the destination port on the selected local endpoint.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	TargetPort int32 `json:"targetPort"`

	// Protocol is the transport protocol used by the frontend and backend.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=TCP;UDP
	Protocol api.L4Proto `json:"protocol"`
}

// CiliumClusterwideLocalRedirectPolicyStatus reports acceptance and local
// reconciliation failures.
// +deepequal-gen=false
type CiliumClusterwideLocalRedirectPolicyStatus struct {
	// Conditions contains policy-level conditions written by the operator.
	//
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// NodeErrors contains the active reconciliation error reported by each node.
	// The key is the Kubernetes node name.
	//
	// +mapType=granular
	// +kubebuilder:validation:Optional
	NodeErrors map[string]CiliumClusterwideLocalRedirectPolicyNodeError `json:"nodeErrors,omitempty"`
}

// CiliumClusterwideLocalRedirectPolicyNodeError describes a node-local error.
// +deepequal-gen=false
type CiliumClusterwideLocalRedirectPolicyNodeError struct {
	// ObservedGeneration is the policy generation that produced this error.
	//
	// +kubebuilder:validation:Required
	ObservedGeneration int64 `json:"observedGeneration"`

	// Reason is a stable, machine-readable error reason.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Reason string `json:"reason"`

	// Message is a human-readable description of the error.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Message string `json:"message"`

	// LastTransitionTime is when this error last changed.
	//
	// +kubebuilder:validation:Required
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`
}

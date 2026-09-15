// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

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
// +kubebuilder:storageversion
// +kubebuilder:object:root=true

// CiliumClusterwideLocalRedirectPolicy is a Kubernetes custom resource that
// contains a specification to redirect traffic locally within a node.
type CiliumClusterwideLocalRedirectPolicy struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	// +kubebuilder:validation:Required
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired behavior of the cluster-wide local redirect policy.
	//
	// +kubebuilder:validation:Required
	Spec CiliumClusterwideLocalRedirectPolicySpec `json:"spec"`
}

// CiliumClusterwideLocalRedirectPolicyList is a list of
// CiliumClusterwideLocalRedirectPolicy objects.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=false
// +deepequal-gen=false
type CiliumClusterwideLocalRedirectPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []CiliumClusterwideLocalRedirectPolicy `json:"items"`
}

// CiliumClusterwideLocalRedirectPolicySpec specifies the configurations for
// redirecting traffic within a node.
//
// +kubebuilder:validation:XValidation:rule="has(self.addressMatcher) != has(self.serviceMatcher)",message="exactly one of addressMatcher or serviceMatcher must be specified"
// +kubebuilder:validation:XValidation:rule="has(self.serviceMatcher) || size(self.ports) > 0",message="ports must be specified with addressMatcher"
type CiliumClusterwideLocalRedirectPolicySpec struct {
	// AddressMatcher matches traffic destined to a single IP address.
	//
	// +kubebuilder:validation:Optional
	AddressMatcher *CiliumClusterwideLocalRedirectPolicyAddressMatcher `json:"addressMatcher,omitempty"`

	// ServiceMatcher matches traffic destined to a Kubernetes Service.
	//
	// +kubebuilder:validation:Optional
	ServiceMatcher *CiliumClusterwideLocalRedirectPolicyServiceMatcher `json:"serviceMatcher,omitempty"`

	// LocalEndpointSelector selects node-local pod(s) where traffic is
	// redirected to.
	//
	// +kubebuilder:validation:Required
	LocalEndpointSelector slim_metav1.LabelSelector `json:"localEndpointSelector"`

	// Ports specifies the source port and protocol to match and the target port
	// on the selected local endpoint(s). When omitted with a serviceMatcher, the
	// Service's port-to-targetPort mappings are inherited.
	//
	// +kubebuilder:validation:Optional
	Ports []CiliumClusterwideLocalRedirectPolicyPort `json:"ports,omitempty"`
}

// CiliumClusterwideLocalRedirectPolicyAddressMatcher matches traffic
// destined to a single IP address.
type CiliumClusterwideLocalRedirectPolicyAddressMatcher struct {
	// IP is the destination IP address for traffic to be redirected.
	// Both IPv4 and IPv6 addresses are supported.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Format=ip
	IP string `json:"ip"`
}

// CiliumClusterwideLocalRedirectPolicyServiceMatcher matches traffic destined
// to a Kubernetes Service.
type CiliumClusterwideLocalRedirectPolicyServiceMatcher struct {
	// ServiceName is the name of the destination Kubernetes Service.
	//
	// +kubebuilder:validation:Required
	ServiceName string `json:"serviceName"`

	// Namespace is the namespace of the destination Kubernetes Service.
	//
	// +kubebuilder:validation:Required
	Namespace string `json:"namespace"`
}

// CiliumClusterwideLocalRedirectPolicyPort specifies a source port and its
// target port along with the transport protocol.
type CiliumClusterwideLocalRedirectPolicyPort struct {
	// Port is the destination port to match. The string is strictly parsed as
	// a single uint16.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^()([1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[0-5])$`
	Port string `json:"port"`

	// TargetPort is the port on the selected local endpoint. The string is
	// strictly parsed as a single uint16.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^()([1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[0-5])$`
	TargetPort string `json:"targetPort"`

	// Protocol is the L4 protocol.
	// Accepted values are TCP and UDP.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=TCP;UDP
	Protocol api.L4Proto `json:"protocol"`
}

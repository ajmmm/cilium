// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/types"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
)

// ClusterwideLocalRedirectPolicy is the normalised, Kubernetes-independent
// representation of a CiliumClusterwideLocalRedirectPolicy. It contains
// policy intent only; concrete Service frontends are resolved separately.
type ClusterwideLocalRedirectPolicy struct {
	// Name is the name of the cluster-scoped Kubernetes resource.
	Name string

	// UID is the unique identifier assigned by Kubernetes.
	UID types.UID

	// AddressMatcher is set when the policy matches a single address.
	AddressMatcher *cmtypes.AddrCluster

	// ServiceMatcher is set when the policy matches a Kubernetes Service.
	ServiceMatcher *lb.ServiceName

	// LocalEndpointSelector selects the endpoints to which traffic is redirected.
	LocalEndpointSelector *policytypes.LabelSelector

	// Ports contains the source-to-target port mappings.
	Ports []ClusterwideLocalRedirectPort
}

// IsAddressMatcher reports whether the policy matches an address. The
// parseCCLRP parser guarantees that exactly one of IsAddressMatcher and
// IsServiceMatcher is true.
func (policy *ClusterwideLocalRedirectPolicy) IsAddressMatcher() bool {
	return policy.AddressMatcher != nil
}

// IsServiceMatcher reports whether the policy matches a Service. The
// parseCCLRP parser guarantees that exactly one of IsAddressMatcher and
// IsServiceMatcher is true.
func (policy *ClusterwideLocalRedirectPolicy) IsServiceMatcher() bool {
	return policy.ServiceMatcher != nil
}

// ClusterwideLocalRedirectPort is a normalised CCLRP source-to-target port mapping.
type ClusterwideLocalRedirectPort struct {
	// Port is the source port on the matched frontend.
	Port uint16

	// TargetPort is the port on the selected local endpoint.
	TargetPort uint16

	// Protocol is the transport protocol used by both the frontend and target.
	Protocol lb.L4Type
}

func (port ClusterwideLocalRedirectPort) String() string {
	return fmt.Sprintf("%d->%d/%s", port.Port, port.TargetPort, port.Protocol)
}

func (policy *ClusterwideLocalRedirectPolicy) TableHeader() []string {
	return []string{
		"Name",
		"Type",
		"Address",
		"Service",
		"Ports",
		"LocalEndpointSelector",
	}
}

func (policy *ClusterwideLocalRedirectPolicy) TableRow() []string {
	matcherType := ""
	address := ""
	service := ""
	switch {
	case policy.IsAddressMatcher():
		matcherType = "address"
		address = policy.AddressMatcher.String()
	case policy.IsServiceMatcher():
		matcherType = "service"
		service = policy.ServiceMatcher.String()
	}

	selector := ""
	if policy.LocalEndpointSelector != nil {
		selector = policy.LocalEndpointSelector.String()
	}

	ports := make([]string, len(policy.Ports))
	for i, port := range policy.Ports {
		ports[i] = port.String()
	}

	return []string{
		policy.Name,
		matcherType,
		address,
		service,
		strings.Join(ports, ", "),
		selector,
	}
}

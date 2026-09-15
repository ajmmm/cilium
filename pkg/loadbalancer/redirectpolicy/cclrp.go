// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/types"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
)

var cclrpLinkLocalPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fe80::/10"),
}

func isCCLRPLinkLocalAddress(address netip.Addr) bool {
	for _, prefix := range cclrpLinkLocalPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

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

func parseCCLRP(cfg Config, clrp *ciliumv2.CiliumClusterwideLocalRedirectPolicy) (*ClusterwideLocalRedirectPolicy, error) {
	if clrp.Name == "" {
		return nil, fmt.Errorf("CiliumClusterwideLocalRedirectPolicy must have a name")
	}

	if (clrp.Spec.AddressMatcher == nil) == (clrp.Spec.ServiceMatcher == nil) {
		return nil, fmt.Errorf("exactly one of addressMatcher or serviceMatcher must be specified")
	}

	policy := &ClusterwideLocalRedirectPolicy{
		Name: clrp.Name,
		UID:  clrp.UID,
	}

	if addressMatcher := clrp.Spec.AddressMatcher; addressMatcher != nil {
		address, err := cmtypes.ParseAddrCluster(addressMatcher.IP)
		if err != nil {
			return nil, fmt.Errorf("invalid address matcher IP %q: %w", addressMatcher.IP, err)
		}
		if !isCCLRPLinkLocalAddress(address.Addr()) {
			return nil, fmt.Errorf("address matcher IP %q must be link-local", addressMatcher.IP)
		}
		if !cfg.AddressAllowed(address.Addr()) {
			return nil, fmt.Errorf("address %q in addressMatcher disallowed by --%s", addressMatcher.IP, AddressMatcherCIDRsName)
		}
		policy.AddressMatcher = &address
	}

	if serviceMatcher := clrp.Spec.ServiceMatcher; serviceMatcher != nil {
		if serviceMatcher.Namespace == "" || serviceMatcher.ServiceName == "" {
			return nil, fmt.Errorf("serviceMatcher namespace and serviceName must not be empty")
		}
		service := lb.NewServiceName(serviceMatcher.Namespace, serviceMatcher.ServiceName)
		policy.ServiceMatcher = &service
	}

	policy.Ports = make([]ClusterwideLocalRedirectPort, len(clrp.Spec.Ports))
	seenPorts := map[struct {
		port     uint16
		protocol lb.L4Type
	}]struct{}{}
	for i, port := range clrp.Spec.Ports {
		parsed, err := parseCCLRPPort(port.Port, port.TargetPort, port.Protocol)
		if err != nil {
			return nil, fmt.Errorf("invalid ports[%d]: %w", i, err)
		}
		key := struct {
			port     uint16
			protocol lb.L4Type
		}{
			port:     parsed.Port,
			protocol: parsed.Protocol,
		}
		if _, found := seenPorts[key]; found {
			return nil, fmt.Errorf("invalid ports[%d]: duplicate port %d/%s", i, parsed.Port, parsed.Protocol)
		}
		seenPorts[key] = struct{}{}
		policy.Ports[i] = parsed
	}

	selector := clrp.Spec.LocalEndpointSelector.DeepCopy()
	policy.LocalEndpointSelector = policytypes.NewLabelSelector(
		api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, selector),
	)

	return policy, nil
}

func parseCCLRPPort(port, targetPort string, protocol api.L4Proto) (ClusterwideLocalRedirectPort, error) {
	parsePort := func(name, value string) (uint16, error) {
		parsed, err := strconv.ParseUint(value, 10, 16)
		if err != nil || parsed == 0 {
			return 0, fmt.Errorf("%s %q is not a valid port number", name, value)
		}
		return uint16(parsed), nil
	}

	portNumber, err := parsePort("port", port)
	if err != nil {
		return ClusterwideLocalRedirectPort{}, err
	}
	targetPortNumber, err := parsePort("targetPort", targetPort)
	if err != nil {
		return ClusterwideLocalRedirectPort{}, err
	}

	var l4Protocol lb.L4Type
	switch protocol {
	case api.ProtoTCP:
		l4Protocol = lb.TCP
	case api.ProtoUDP:
		l4Protocol = lb.UDP
	default:
		return ClusterwideLocalRedirectPort{}, fmt.Errorf("protocol %q is not supported", protocol)
	}

	return ClusterwideLocalRedirectPort{
		Port:       portNumber,
		TargetPort: targetPortNumber,
		Protocol:   l4Protocol,
	}, nil
}

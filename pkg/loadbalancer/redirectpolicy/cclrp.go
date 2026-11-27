// This file was not reviewed by a human before submission
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/types"

	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/labels"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
)

// ClusterwideLocalRedirectPolicy is the normalized CCLRP intent reflected from
// Kubernetes. It contains no per-node or load-balancer frontend state.
type ClusterwideLocalRedirectPolicy struct {
	Name                  string
	UID                   types.UID
	Generation            int64
	BackendNamespace      string
	LocalEndpointSelector *policytypes.LabelSelector
	AddressMatcher        *netip.Addr
	ServiceMatcher        *lb.ServiceName
	Ports                 []clusterwideLocalRedirectPort
}

// clusterwideLocalRedirectPort maps one frontend port to a local endpoint
// port for a specific transport protocol.
type clusterwideLocalRedirectPort struct {
	Port       uint16
	TargetPort uint16
	Protocol   lb.L4Type
}

func (port clusterwideLocalRedirectPort) String() string {
	return fmt.Sprintf("%d->%d/%s", port.Port, port.TargetPort, port.Protocol)
}

func (policy *ClusterwideLocalRedirectPolicy) TableHeader() []string {
	return []string{"Name", "BackendNamespace", "Matcher", "Ports", "Selector"}
}

func (policy *ClusterwideLocalRedirectPolicy) TableRow() []string {
	matcher := ""
	switch {
	case policy.AddressMatcher != nil:
		matcher = "address=" + policy.AddressMatcher.String()
	case policy.ServiceMatcher != nil:
		matcher = "service=" + policy.ServiceMatcher.String()
	}
	ports := make([]string, len(policy.Ports))
	for i, port := range policy.Ports {
		ports[i] = port.String()
	}
	selector := ""
	if policy.LocalEndpointSelector != nil {
		selector = policy.LocalEndpointSelector.String()
	}
	return []string{policy.Name, policy.BackendNamespace, matcher, strings.Join(ports, ", "), selector}
}

func parseCCLRP(clrp *ciliumv2alpha1.CiliumClusterwideLocalRedirectPolicy) (*ClusterwideLocalRedirectPolicy, error) {
	if clrp.Name == "" {
		return nil, fmt.Errorf("CiliumClusterwideLocalRedirectPolicy must have a name")
	}
	if clrp.Spec.BackendNamespace == "" {
		return nil, fmt.Errorf("backendNamespace must not be empty")
	}
	if (clrp.Spec.AddressMatcher == nil) == (clrp.Spec.ServiceMatcher == nil) {
		return nil, fmt.Errorf("exactly one of addressMatcher or serviceMatcher must be specified")
	}
	if len(clrp.Spec.Ports) == 0 {
		return nil, fmt.Errorf("at least one explicit port mapping is required")
	}

	policy := &ClusterwideLocalRedirectPolicy{
		Name:             clrp.Name,
		UID:              clrp.UID,
		Generation:       clrp.Generation,
		BackendNamespace: clrp.Spec.BackendNamespace,
	}

	if matcher := clrp.Spec.AddressMatcher; matcher != nil {
		address, err := netip.ParseAddr(matcher.IP)
		if err != nil {
			return nil, fmt.Errorf("invalid addressMatcher IP %q: %w", matcher.IP, err)
		}
		if !address.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("addressMatcher IP %q must be link-local unicast", matcher.IP)
		}
		policy.AddressMatcher = &address
	}
	if matcher := clrp.Spec.ServiceMatcher; matcher != nil {
		if matcher.Namespace == "" || matcher.ServiceName == "" {
			return nil, fmt.Errorf("serviceMatcher namespace and serviceName must not be empty")
		}
		service := lb.NewServiceName(matcher.Namespace, matcher.ServiceName)
		policy.ServiceMatcher = &service
	}

	selector := clrp.Spec.LocalEndpointSelector.DeepCopy()
	policy.LocalEndpointSelector = policytypes.NewLabelSelector(
		api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, selector),
	)

	seen := map[struct {
		port     uint16
		protocol lb.L4Type
	}]struct{}{}
	for i, port := range clrp.Spec.Ports {
		parsed, err := parseClusterwideLocalRedirectPort(port.Port, port.TargetPort, port.Protocol)
		if err != nil {
			return nil, fmt.Errorf("invalid ports[%d]: %w", i, err)
		}
		key := struct {
			port     uint16
			protocol lb.L4Type
		}{parsed.Port, parsed.Protocol}
		if _, found := seen[key]; found {
			return nil, fmt.Errorf("duplicate frontend port %d/%s", parsed.Port, parsed.Protocol)
		}
		seen[key] = struct{}{}
		policy.Ports = append(policy.Ports, parsed)
	}

	return policy, nil
}

func parseClusterwideLocalRedirectPort(port, targetPort int32, protocol api.L4Proto) (clusterwideLocalRedirectPort, error) {
	parsePort := func(name string, value int32) (uint16, error) {
		if value < 1 || value > 65535 {
			return 0, fmt.Errorf("%s %q is not a valid port number", name, strconv.FormatInt(int64(value), 10))
		}
		return uint16(value), nil
	}

	frontendPort, err := parsePort("port", port)
	if err != nil {
		return clusterwideLocalRedirectPort{}, err
	}
	backendPort, err := parsePort("targetPort", targetPort)
	if err != nil {
		return clusterwideLocalRedirectPort{}, err
	}

	var l4Protocol lb.L4Type
	switch protocol {
	case api.ProtoTCP:
		l4Protocol = lb.TCP
	case api.ProtoUDP:
		l4Protocol = lb.UDP
	default:
		return clusterwideLocalRedirectPort{}, fmt.Errorf("protocol %q is not supported", protocol)
	}

	return clusterwideLocalRedirectPort{Port: frontendPort, TargetPort: backendPort, Protocol: l4Protocol}, nil
}

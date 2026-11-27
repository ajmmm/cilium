// This file was not reviewed by a human before submission
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/util/sets"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	ciliumLabels "github.com/cilium/cilium/pkg/labels"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
)

type cclrpControllerParams struct {
	cell.In

	Config   Config
	Log      *slog.Logger
	DB       *statedb.DB
	Policies statedb.Table[*ClusterwideLocalRedirectPolicy]
	States   statedb.RWTable[*ClusterwideLocalRedirectPolicyState]
	Pods     statedb.Table[k8sTables.LocalPod]
	Writer   *writer.Writer
}

type cclrpController struct {
	p cclrpControllerParams
}

func newCCLRPController(params cclrpControllerParams) *cclrpController {
	return &cclrpController{p: params}
}

func registerCCLRPController(g job.Group, controller *cclrpController) {
	if controller.p.Config.IsEnabled() {
		g.Add(job.OneShot("cclrp-controller", controller.run))
	}
}

func (c *cclrpController) run(ctx context.Context, health cell.Health) error {
	const waitTime = 100 * time.Millisecond
	const initializerName = "cclrp-controller"

	lbInit := c.p.Writer.RegisterInitializer(initializerName)
	wtxn := c.p.DB.WriteTxn(c.p.States)
	stateInit := c.p.States.RegisterInitializer(wtxn, initializerName)
	wtxn.Commit()

	for {
		wtxn := c.p.Writer.WriteTxn(c.p.States)
		watchSet := statedb.NewWatchSet()

		policies, policiesWatch := c.p.Policies.AllWatch(wtxn)
		watchSet.Add(policiesWatch)
		pods, podsWatch := c.p.Pods.AllWatch(wtxn)
		watchSet.Add(podsWatch)
		frontends, frontendsWatch := c.p.Writer.Frontends().AllWatch(wtxn)
		watchSet.Add(frontendsWatch)

		_, policiesInitWatch := c.p.Policies.Initialized(wtxn)
		_, podsInitWatch := c.p.Pods.Initialized(wtxn)
		_, frontendsInitWatch := c.p.Writer.Frontends().Initialized(wtxn)
		if !watchClosed(policiesInitWatch) || !watchClosed(podsInitWatch) || !watchClosed(frontendsInitWatch) {
			wtxn.Commit()
			if _, err := watchSet.Wait(ctx, waitTime); err != nil {
				return err
			}
			continue
		}

		policyList := make([]*ClusterwideLocalRedirectPolicy, 0)
		for policy := range policies {
			policyList = append(policyList, policy)
		}
		podList := make([]k8sTables.LocalPod, 0)
		for pod := range pods {
			podList = append(podList, pod)
		}
		frontendList := make([]*lb.Frontend, 0)
		for frontend := range frontends {
			frontendList = append(frontendList, frontend)
		}
		plans := c.compile(policyList, podList, frontendList)
		active := sets.New[string]()
		retry := false

		for _, plan := range plans {
			active.Insert(plan.policy.Name)
			previous, _, found := c.p.States.Get(wtxn, cclrpStateNameIndex.Query(plan.policy.Name))
			if !found {
				previous = nil
			}
			if err := c.apply(wtxn, plan, previous); err != nil {
				plan.state.Error = err.Error()
				retry = true
				health.Degraded("Failed to reconcile CCLRP", err)
				c.p.Log.Error("Failed to reconcile CCLRP",
					logfields.Name, plan.policy.Name,
					logfields.Error, err)
			}
			c.insertState(wtxn, plan.state)
		}

		for state := range c.p.States.All(wtxn) {
			if active.Has(state.Name) {
				continue
			}
			if err := c.cleanupPolicy(wtxn, state); err != nil {
				retry = true
				health.Degraded("Failed to clean up CCLRP", err)
				c.p.Log.Error("Failed to clean up CCLRP", logfields.Name, state.Name, logfields.Error, err)
				continue
			}
			c.p.States.Delete(wtxn, state)
		}

		if stateInit != nil {
			stateInit(wtxn)
			stateInit = nil
		}
		if lbInit != nil {
			lbInit(wtxn)
			lbInit = nil
		}
		wtxn.Commit()

		if retry {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(waitTime):
			}
			continue
		}
		if _, err := watchSet.Wait(ctx, waitTime); err != nil {
			return err
		}
	}
}

type cclrpMappingPlan struct {
	policyName       string
	port             clusterwideLocalRedirectPort
	serviceName      lb.ServiceName
	backends         []lb.Backend
	frontends        []*lb.Frontend
	matchedFrontends int
	error            string
}

type cclrpPlan struct {
	policy   *ClusterwideLocalRedirectPolicy
	state    *ClusterwideLocalRedirectPolicyState
	mappings []*cclrpMappingPlan
}

func (c *cclrpController) compile(
	policies []*ClusterwideLocalRedirectPolicy,
	pods []k8sTables.LocalPod,
	frontends []*lb.Frontend,
) []*cclrpPlan {
	plans := make([]*cclrpPlan, 0, len(policies))
	claims := map[lb.L3n4Addr][]*cclrpMappingPlan{}
	frontendsByService := map[lb.ServiceName][]*lb.Frontend{}
	frontendsByAddress := map[lb.L3n4Addr]*lb.Frontend{}
	for _, frontend := range frontends {
		frontendsByService[frontend.ServiceName] = append(frontendsByService[frontend.ServiceName], frontend)
		frontendsByAddress[frontend.Address] = frontend
	}

	for _, policy := range policies {
		plan := c.compilePolicy(policy, pods)
		plans = append(plans, plan)

		for _, mapping := range plan.mappings {
			if policy.AddressMatcher != nil {
				if len(mapping.backends) > 0 {
					mapping.matchedFrontends = 1
				}
				frontendAddress := lb.NewL3n4Addr(mapping.port.Protocol, cmtypes.AddrClusterFrom(*policy.AddressMatcher, 0), mapping.port.Port, lb.ScopeExternal)
				if existing := frontendsByAddress[frontendAddress]; existing != nil &&
					(existing.Type != lb.SVCTypeLocalRedirect || !existing.ServiceName.Equal(mapping.serviceName)) {
					mapping.error = fmt.Sprintf("address %s is owned by service %s", frontendAddress.StringWithProtocol(), existing.ServiceName)
				}
				claims[frontendAddress] = append(claims[frontendAddress], mapping)
				continue
			}

			for _, frontend := range frontendsByService[*policy.ServiceMatcher] {
				if frontend.Type != lb.SVCTypeClusterIP || !matchesCCLRPPort(frontend, mapping.port) {
					continue
				}
				mapping.matchedFrontends++
				mapping.frontends = append(mapping.frontends, frontend)
				if frontend.RedirectTo != nil && !frontend.RedirectTo.Equal(mapping.serviceName) {
					mapping.error = fmt.Sprintf("frontend %s is already redirected to service %s", frontend.Address.StringWithProtocol(), *frontend.RedirectTo)
				}
				claims[frontend.Address] = append(claims[frontend.Address], mapping)
			}
		}
	}

	for frontend, frontendClaims := range claims {
		if len(frontendClaims) < 2 {
			continue
		}
		policyNames := sets.New[string]()
		for _, mapping := range frontendClaims {
			policyNames.Insert(mapping.policyName)
		}
		names := policyNames.UnsortedList()
		slices.Sort(names)
		err := fmt.Sprintf("frontend %s is claimed by multiple CCLRPs: %s", frontend.StringWithProtocol(), strings.Join(names, ", "))
		for _, mapping := range frontendClaims {
			mapping.error = err
		}
	}

	for _, plan := range plans {
		for _, mapping := range plan.mappings {
			backendAddresses := make([]lb.L3n4Addr, len(mapping.backends))
			for i, backend := range mapping.backends {
				backendAddresses[i] = backend.Address
			}
			plan.state.Mappings = append(plan.state.Mappings, ClusterwideLocalRedirectPolicyPortState{
				Port:                 mapping.port.Port,
				TargetPort:           mapping.port.TargetPort,
				Protocol:             mapping.port.Protocol,
				Backends:             backendAddresses,
				MatchedFrontendCount: mapping.matchedFrontends,
				Error:                mapping.error,
			})
			if mapping.error != "" {
				plan.state.Error = appendError(plan.state.Error, mapping.error)
			}
		}
	}

	return plans
}

func (c *cclrpController) compilePolicy(policy *ClusterwideLocalRedirectPolicy, pods []k8sTables.LocalPod) *cclrpPlan {
	state := &ClusterwideLocalRedirectPolicyState{
		Name:             policy.Name,
		UID:              string(policy.UID),
		Generation:       policy.Generation,
		BackendNamespace: policy.BackendNamespace,
	}
	if policy.AddressMatcher != nil {
		address := *policy.AddressMatcher
		state.AddressMatcher = &address
	}
	if policy.ServiceMatcher != nil {
		service := *policy.ServiceMatcher
		state.ServiceMatcher = &service
	}

	plan := &cclrpPlan{policy: policy, state: state}
	for _, port := range policy.Ports {
		mapping := &cclrpMappingPlan{
			policyName:  policy.Name,
			port:        port,
			serviceName: cclrpMappingServiceName(policy.Name, port),
		}
		backends := map[lb.L3n4Addr]lb.Backend{}
		for _, pod := range pods {
			if pod.Namespace != policy.BackendNamespace ||
				k8sUtils.GetLatestPodReadiness(pod.Status) != slim_corev1.ConditionTrue ||
				!policytypes.Matches(policy.LocalEndpointSelector, ciliumLabels.K8sSet(pod.Labels)) {
				continue
			}
			for _, ip := range localPodIPs(pod) {
				address := lb.NewL3n4Addr(port.Protocol, cmtypes.AddrClusterFrom(ip, 0), port.TargetPort, lb.ScopeExternal)
				backends[address] = lb.Backend{Address: address, State: lb.BackendStateActive}
			}
		}
		for _, backend := range backends {
			mapping.backends = append(mapping.backends, backend)
		}
		slices.SortFunc(mapping.backends, func(a, b lb.Backend) int {
			return strings.Compare(a.Address.StringWithProtocol(), b.Address.StringWithProtocol())
		})
		plan.mappings = append(plan.mappings, mapping)
	}
	return plan
}

func localPodIPs(pod k8sTables.LocalPod) []netip.Addr {
	seen := map[netip.Addr]struct{}{}
	ips := make([]netip.Addr, 0, len(pod.Status.PodIPs)+1)
	appendIP := func(raw string) {
		ip, err := netip.ParseAddr(raw)
		if err != nil || !ip.IsValid() {
			return
		}
		if _, found := seen[ip]; found {
			return
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
	}
	for _, podIP := range pod.Status.PodIPs {
		appendIP(podIP.IP)
	}
	if len(ips) == 0 {
		appendIP(pod.Status.PodIP)
	}
	return ips
}

func (c *cclrpController) apply(wtxn writer.WriteTxn, plan *cclrpPlan, previous *ClusterwideLocalRedirectPolicyState) error {
	activeMappings := map[string]struct{}{}
	for _, mapping := range plan.mappings {
		activeMappings[cclrpPortKey(mapping.port.Port, mapping.port.Protocol)] = struct{}{}
	}
	if previous != nil {
		for _, mapping := range previous.Mappings {
			if _, found := activeMappings[cclrpPortKey(mapping.Port, mapping.Protocol)]; found {
				continue
			}
			oldPort := clusterwideLocalRedirectPort{Port: mapping.Port, Protocol: mapping.Protocol}
			if err := c.cleanupMapping(wtxn, cclrpMappingServiceName(plan.policy.Name, oldPort)); err != nil {
				return fmt.Errorf("remove stale mapping %s: %w", oldPort, err)
			}
		}
	}

	for _, mapping := range plan.mappings {
		service := &lb.Service{
			Name:             mapping.serviceName,
			Source:           source.Kubernetes,
			ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
			IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
		}
		if _, err := c.p.Writer.UpsertService(wtxn, service); err != nil {
			return fmt.Errorf("upsert pseudo service: %w", err)
		}
		backends := mapping.backends
		if mapping.error != "" {
			backends = nil
		}
		backendsChanged, err := c.setBackendsIfChanged(wtxn, mapping.serviceName, backends)
		if err != nil {
			return fmt.Errorf("set pseudo service backends: %w", err)
		}
		if backendsChanged && plan.policy.ServiceMatcher != nil {
			if err := c.p.Writer.RefreshFrontends(wtxn, *plan.policy.ServiceMatcher); err != nil {
				return fmt.Errorf("refresh redirected Service frontends: %w", err)
			}
		}

		if plan.policy.AddressMatcher != nil {
			c.clearRedirects(wtxn, mapping.serviceName)
			var frontends []lb.FrontendParams
			if len(backends) > 0 && mapping.error == "" {
				address := lb.NewL3n4Addr(mapping.port.Protocol, cmtypes.AddrClusterFrom(*plan.policy.AddressMatcher, 0), mapping.port.Port, lb.ScopeExternal)
				frontends = append(frontends, lb.FrontendParams{
					Address:     address,
					Type:        lb.SVCTypeLocalRedirect,
					ServiceName: mapping.serviceName,
					ServicePort: mapping.port.Port,
				})
			}
			if err := c.p.Writer.UpsertServiceAndFrontends(wtxn, service, frontends...); err != nil {
				return fmt.Errorf("upsert address matcher frontend: %w", err)
			}
			continue
		}

		c.removePseudoFrontends(wtxn, mapping.serviceName)
		matching := map[lb.L3n4Addr]struct{}{}
		for _, frontend := range mapping.frontends {
			matching[frontend.Address] = struct{}{}
			if mapping.error != "" || len(backends) == 0 {
				if frontend.RedirectTo != nil && frontend.RedirectTo.Equal(mapping.serviceName) {
					c.p.Writer.SetRedirectTo(wtxn, frontend, nil)
				}
				continue
			}
			if frontend.RedirectTo == nil || frontend.RedirectTo.Equal(mapping.serviceName) {
				c.p.Writer.SetRedirectTo(wtxn, frontend, &mapping.serviceName)
			}
		}
		for frontend := range c.p.Writer.Frontends().All(wtxn) {
			if frontend.RedirectTo == nil || !frontend.RedirectTo.Equal(mapping.serviceName) {
				continue
			}
			if _, found := matching[frontend.Address]; !found {
				c.p.Writer.SetRedirectTo(wtxn, frontend, nil)
			}
		}
	}
	return nil
}

func matchesCCLRPPort(frontend *lb.Frontend, port clusterwideLocalRedirectPort) bool {
	return frontend.ServicePort == port.Port && frontend.Address.Protocol() == port.Protocol
}

func (c *cclrpController) setBackendsIfChanged(wtxn writer.WriteTxn, serviceName lb.ServiceName, desired []lb.Backend) (bool, error) {
	desiredSet := make(map[lb.L3n4Addr]struct{}, len(desired))
	for _, backend := range desired {
		desiredSet[backend.Address] = struct{}{}
	}
	currentSet := map[lb.L3n4Addr]struct{}{}
	for backend := range lb.ListBackendsByServiceName(wtxn, c.p.Writer.Backends(), serviceName) {
		if backend.Source == source.Kubernetes && backend.ClusterID == lb.LocalClusterID {
			currentSet[backend.Address] = struct{}{}
		}
	}
	if maps.Equal(currentSet, desiredSet) {
		return false, nil
	}
	if err := c.p.Writer.SetBackends(wtxn, serviceName, source.Kubernetes, desired...); err != nil {
		return false, err
	}
	return true, nil
}

func (c *cclrpController) removePseudoFrontends(wtxn writer.WriteTxn, serviceName lb.ServiceName) {
	for frontend := range c.p.Writer.Frontends().List(wtxn, lb.FrontendByServiceName(serviceName)) {
		c.p.Writer.DeleteFrontend(wtxn, frontend.Address)
	}
}

func (c *cclrpController) cleanupPolicy(wtxn writer.WriteTxn, state *ClusterwideLocalRedirectPolicyState) error {
	for _, mapping := range state.Mappings {
		if err := c.cleanupMapping(wtxn, cclrpMappingServiceName(state.Name, clusterwideLocalRedirectPort{
			Port:     mapping.Port,
			Protocol: mapping.Protocol,
		})); err != nil {
			return err
		}
	}
	return nil
}

func (c *cclrpController) cleanupMapping(wtxn writer.WriteTxn, serviceName lb.ServiceName) error {
	c.clearRedirects(wtxn, serviceName)
	if err := c.p.Writer.DeleteBackendsOfService(wtxn, serviceName, source.Kubernetes); err != nil {
		return err
	}
	if _, err := c.p.Writer.DeleteServiceAndFrontends(wtxn, serviceName); err != nil && !errors.Is(err, statedb.ErrObjectNotFound) {
		return err
	}
	return nil
}

func (c *cclrpController) clearRedirects(wtxn writer.WriteTxn, serviceName lb.ServiceName) {
	for frontend := range c.p.Writer.Frontends().All(wtxn) {
		if frontend.RedirectTo != nil && frontend.RedirectTo.Equal(serviceName) {
			c.p.Writer.SetRedirectTo(wtxn, frontend, nil)
		}
	}
}

func (c *cclrpController) insertState(wtxn writer.WriteTxn, state *ClusterwideLocalRedirectPolicyState) {
	current, _, found := c.p.States.Get(wtxn, cclrpStateNameIndex.Query(state.Name))
	if found && reflect.DeepEqual(current, state) {
		return
	}
	if _, _, err := c.p.States.Insert(wtxn, state); err != nil {
		c.p.Log.Error("Failed to update compiled CCLRP state", logfields.Name, state.Name, logfields.Error, err)
	}
}

func cclrpMappingServiceName(policyName string, port clusterwideLocalRedirectPort) lb.ServiceName {
	key := fmt.Sprintf("%s\x00%d\x00%s", policyName, port.Port, port.Protocol)
	sum := sha256.Sum256([]byte(key))
	return lb.NewServiceName("cilium", "cclrp-"+hex.EncodeToString(sum[:8]))
}

func cclrpPortKey(port uint16, protocol lb.L4Type) string {
	return fmt.Sprintf("%d/%s", port, protocol)
}

func appendError(existing, next string) string {
	if existing == "" {
		return next
	}
	if strings.Contains(existing, next) {
		return existing
	}
	return existing + "; " + next
}

func watchClosed(watch <-chan struct{}) bool {
	if watch == nil {
		return true
	}
	select {
	case <-watch:
		return true
	default:
		return false
	}
}

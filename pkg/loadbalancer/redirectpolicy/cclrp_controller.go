// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	ciliumLabels "github.com/cilium/cilium/pkg/labels"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

type cclrpControllerParams struct {
	cell.In

	Config Config

	Log *slog.Logger

	DB *statedb.DB

	Policies statedb.Table[*ClusterwideLocalRedirectPolicy]

	Mappings statedb.RWTable[*ClusterwideLocalRedirectMapping]

	Pods statedb.Table[k8sTables.LocalPod]

	Writer *writer.Writer
}

// cclrpController applies concrete CCLRP mappings to load-balancer state.
type cclrpController struct {
	Config Config

	Log *slog.Logger

	DB *statedb.DB

	Policies statedb.Table[*ClusterwideLocalRedirectPolicy]

	Mappings statedb.RWTable[*ClusterwideLocalRedirectMapping]

	Pods statedb.Table[k8sTables.LocalPod]

	Writer *writer.Writer
}

func newCCLRPController(params cclrpControllerParams) *cclrpController {
	return &cclrpController{
		Config:   params.Config,
		Log:      params.Log,
		DB:       params.DB,
		Policies: params.Policies,
		Mappings: params.Mappings,
		Pods:     params.Pods,
		Writer:   params.Writer,
	}
}

func registerCCLRPController(g job.Group, controller *cclrpController) {
	if !controller.Config.IsEnabled() {
		return
	}
	g.Add(job.OneShot("cclrp-controller", controller.run))
}

func (controller *cclrpController) run(ctx context.Context, health cell.Health) error {
	const waitTime = 100 * time.Millisecond

	knownPolicies := map[string]lb.ServiceName{}
	for {
		// Watch CCLRP intent, concrete mappings, matching Pods, and the relevant
		// load-balancer frontends. Changes update the CCLRP pseudo-services,
		// local backends, frontend redirects, and clean up removed policies.
		allWatches := statedb.NewWatchSet()
		wtxn := controller.Writer.WriteTxn(controller.Mappings)

		_, policiesInitWatch := controller.Policies.Initialized(wtxn)
		allWatches.Add(policiesInitWatch)
		_, mappingsInitWatch := controller.Mappings.Initialized(wtxn)
		allWatches.Add(mappingsInitWatch)
		_, podsInitWatch := controller.Pods.Initialized(wtxn)
		allWatches.Add(podsInitWatch)

		policies, policiesWatch := controller.Policies.AllWatch(wtxn)
		allWatches.Add(policiesWatch)
		mappings, mappingsWatch := controller.Mappings.AllWatch(wtxn)
		allWatches.Add(mappingsWatch)

		mappingsByPolicy := map[string][]*ClusterwideLocalRedirectMapping{}
		for mapping := range mappings {
			mappingsByPolicy[mapping.PolicyName] = append(mappingsByPolicy[mapping.PolicyName], mapping)
		}

		activePolicies := map[string]lb.ServiceName{}
		reconcileFailed := false
		for policy := range policies {
			activePolicies[policy.Name] = policy.RedirectServiceName()
			if controller.reconcilePolicy(wtxn, allWatches, health, policy, mappingsByPolicy[policy.Name]) {
				reconcileFailed = true
			}
		}

		cleanupFailed := false
		for policyName, serviceName := range knownPolicies {
			if _, found := activePolicies[policyName]; found {
				continue
			}
			if err := controller.cleanupPolicy(wtxn, serviceName); err != nil {
				cleanupFailed = true
				activePolicies[policyName] = serviceName
				health.Degraded("Failed to clean up CCLRP", err)
				controller.Log.Error("Failed to clean up CCLRP", "policy", policyName, "error", err)
			}
		}
		knownPolicies = activePolicies

		wtxn.Commit()
		if reconcileFailed || cleanupFailed {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(waitTime):
			}
			continue
		}

		if _, err := allWatches.Wait(ctx, waitTime); err != nil {
			return err
		}
	}
}

func (controller *cclrpController) reconcilePolicy(
	wtxn writer.WriteTxn,
	allWatches *statedb.WatchSet,
	health cell.Health,
	policy *ClusterwideLocalRedirectPolicy,
	mappings []*ClusterwideLocalRedirectMapping,
) (retry bool) {
	serviceName := policy.RedirectServiceName()
	_, err := controller.Writer.UpsertService(wtxn, &lb.Service{
		Name:             serviceName,
		Source:           source.Kubernetes,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
	})
	if err != nil {
		health.Degraded("Failed to upsert CCLRP service", err)
		controller.Log.Error("Failed to upsert CCLRP service", "policy", policy.Name, "error", err)
		return true
	}

	matchingPods := controller.matchingPods(wtxn, allWatches, policy)
	backends := map[string]lb.Backend{}
	addressFrontends := make([]lb.FrontendParams, 0, len(mappings))
	serviceFrontends := map[string]struct{}{}
	successfulMappings := make([]*ClusterwideLocalRedirectMapping, 0, len(mappings))

	for _, mapping := range mappings {
		if mapping.Status.Kind == reconciler.StatusKindError {
			continue
		}
		frontend, _, frontendWatch, found := controller.Writer.Frontends().GetWatch(wtxn, lb.FrontendByAddress(mapping.FrontendAddress))
		allWatches.Add(frontendWatch)

		if policy.IsServiceMatcher() && !found {
			continue
		}

		portName := cclrpMappingPortName(mapping, frontend)
		if len(matchingPods) > 0 {
			for _, pod := range matchingPods {
				for _, podIP := range pod.ips {
					backendAddress := lb.NewL3n4Addr(
						mapping.TargetPort.Protocol,
						podIP,
						mapping.TargetPort.Port,
						lb.ScopeExternal,
					)
					key := backendAddress.StringWithProtocol()
					backend := backends[key]
					if backend.Address == (lb.L3n4Addr{}) {
						backend = lb.Backend{
							Address: backendAddress,
							State:   lb.BackendStateActive,
						}
					}
					if portName != "" && !slices.Contains(backend.PortNames, string(portName)) {
						backend.PortNames = append(backend.PortNames, string(portName))
					}
					backends[key] = backend
				}
			}

			if policy.IsAddressMatcher() {
				addressFrontends = append(addressFrontends, lb.FrontendParams{
					Address:     mapping.FrontendAddress,
					Type:        lb.SVCTypeLocalRedirect,
					ServiceName: serviceName,
					PortName:    portName,
					ServicePort: mapping.FrontendAddress.Port(),
				})
			} else if found {
				serviceFrontends[mapping.FrontendAddress.StringWithProtocol()] = struct{}{}
			}
			successfulMappings = append(successfulMappings, mapping)
		}
	}

	backendList := make([]lb.Backend, 0, len(backends))
	for _, backend := range backends {
		backendList = append(backendList, backend)
	}
	// The controller watches frontends, and RefreshFrontends publishes a new
	// frontend revision even when its effective backends are unchanged. Only
	// refresh after a real backend-set change, otherwise the controller would
	// repeatedly wake itself from its own frontend writes.
	backendsChanged, err := controller.Writer.SetBackendsOfClusterIfChanged(wtxn, serviceName, source.Kubernetes, backendList...)
	if err != nil {
		health.Degraded("Failed to set CCLRP backends", err)
		controller.Log.Error("Failed to set CCLRP backends", "policy", policy.Name, "error", err)
		return true
	}

	if policy.IsAddressMatcher() {
		for _, mapping := range mappings {
			if mapping.Status.Kind == reconciler.StatusKindError {
				continue
			}
			existing, _, found := controller.Writer.Frontends().Get(wtxn, lb.FrontendByAddress(mapping.FrontendAddress))
			if found && existing.Type == lb.SVCTypeLocalRedirect && !existing.ServiceName.Equal(serviceName) {
				controller.Writer.DeleteFrontend(wtxn, mapping.FrontendAddress)
			}
		}
		controller.clearStaleRedirects(wtxn, serviceName, nil)
		if err := controller.Writer.UpsertServiceAndFrontends(wtxn, &lb.Service{
			Name:             serviceName,
			Source:           source.Kubernetes,
			ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
			IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
		}, addressFrontends...); err != nil {
			health.Degraded("Failed to upsert CCLRP frontends", err)
			controller.Log.Error("Failed to upsert CCLRP frontends", "policy", policy.Name, "error", err)
			return true
		}
	} else {
		// A policy can change from address-based to service-based while retaining
		// its name. Remove any frontends left behind by the old policy form.
		for frontend := range controller.Writer.Frontends().List(wtxn, lb.FrontendByServiceName(serviceName)) {
			controller.Writer.DeleteFrontend(wtxn, frontend.Address)
		}

		// Remove redirects left on an old Service target, while retaining redirects
		// that this policy still wants on the current target.
		controller.clearStaleRedirects(wtxn, serviceName, serviceFrontends)

		_, frontendsWatch := controller.Writer.Frontends().ListWatch(wtxn, lb.FrontendByServiceName(*policy.ServiceMatcher))
		allWatches.Add(frontendsWatch)
		for _, mapping := range mappings {
			if mapping.Status.Kind == reconciler.StatusKindError {
				continue
			}
			frontend, _, _, found := controller.Writer.Frontends().GetWatch(wtxn, lb.FrontendByAddress(mapping.FrontendAddress))
			if !found {
				continue
			}
			if len(matchingPods) == 0 {
				// A valid CCLRP mapping claims the frontend even when there are
				// currently no local endpoints. Clear any legacy redirect so that
				// CLRP cannot continue serving traffic through its pseudo-service.
				controller.Writer.SetRedirectTo(wtxn, frontend, nil)
			}
		}
		if len(matchingPods) > 0 {
			for _, mapping := range successfulMappings {
				frontend, _, _, found := controller.Writer.Frontends().GetWatch(wtxn, lb.FrontendByAddress(mapping.FrontendAddress))
				if found {
					controller.Writer.SetRedirectTo(wtxn, frontend, &serviceName)
				}
			}
		}
		if backendsChanged {
			if err := controller.Writer.RefreshFrontends(wtxn, *policy.ServiceMatcher); err != nil {
				health.Degraded("Failed to refresh CCLRP service frontends", err)
				controller.Log.Error("Failed to refresh CCLRP service frontends", "policy", policy.Name, "error", err)
				return true
			}
		}
	}

	for _, mapping := range successfulMappings {
		if err := setCCLRPMappingStatus(wtxn, controller.Mappings, mapping, reconciler.StatusDone()); err != nil {
			health.Degraded("Failed to update CCLRP mapping status", err)
			controller.Log.Error("Failed to update CCLRP mapping status", "policy", policy.Name, "error", err)
			return true
		}
	}
	return false
}

func (controller *cclrpController) matchingPods(
	txn statedb.ReadTxn,
	allWatches *statedb.WatchSet,
	policy *ClusterwideLocalRedirectPolicy,
) []podInfo {
	pods, podsWatch := controller.Pods.AllWatch(txn)
	allWatches.Add(podsWatch)

	matchingPods := make([]podInfo, 0)
	for pod := range pods {
		if k8sUtils.GetLatestPodReadiness(pod.Status) != slim_corev1.ConditionTrue {
			continue
		}
		podLabels := ciliumLabels.K8sSet(pod.Labels)
		podLabels[k8sConst.PodNamespaceLabel] = pod.Namespace
		if types.Matches(policy.LocalEndpointSelector, podLabels) {
			matchingPods = append(matchingPods, getPodInfo(pod))
		}
	}
	return matchingPods
}

func (controller *cclrpController) clearStaleRedirects(
	txn writer.WriteTxn,
	serviceName lb.ServiceName,
	keep map[string]struct{},
) {
	for frontend := range controller.Writer.Frontends().All(txn) {
		if frontend.RedirectTo == nil || !frontend.RedirectTo.Equal(serviceName) {
			continue
		}
		if _, found := keep[frontend.Address.StringWithProtocol()]; found {
			continue
		}
		controller.Writer.SetRedirectTo(txn, frontend, nil)
	}
}

func (controller *cclrpController) cleanupPolicy(txn writer.WriteTxn, serviceName lb.ServiceName) error {
	for frontend := range controller.Writer.Frontends().All(txn) {
		if frontend.RedirectTo != nil && frontend.RedirectTo.Equal(serviceName) {
			controller.Writer.SetRedirectTo(txn, frontend, nil)
		}
	}
	if err := controller.Writer.DeleteBackendsOfService(txn, serviceName, source.Kubernetes); err != nil {
		return err
	}
	if _, err := controller.Writer.DeleteServiceAndFrontends(txn, serviceName); err != nil && !errors.Is(err, statedb.ErrObjectNotFound) {
		return err
	}
	return nil
}

func cclrpMappingPortName(mapping *ClusterwideLocalRedirectMapping, frontend *lb.Frontend) lb.FEPortName {
	if frontend != nil && frontend.PortName != "" {
		return frontend.PortName
	}
	return lb.FEPortName(fmt.Sprintf("cclrp-%d-%s", mapping.FrontendAddress.Port(), mapping.FrontendAddress.Protocol()))
}

func setCCLRPMappingStatus(
	txn writer.WriteTxn,
	mappings statedb.RWTable[*ClusterwideLocalRedirectMapping],
	mapping *ClusterwideLocalRedirectMapping,
	status reconciler.Status,
) error {
	if mapping.Status.Kind == status.Kind {
		// Status updates are also StateDB events. Do not reinsert an unchanged
		// status, or each controller pass would create another mapping event.
		return nil
	}
	updated := *mapping
	updated.Status = status
	_, _, err := mappings.Insert(txn, &updated)
	return err
}

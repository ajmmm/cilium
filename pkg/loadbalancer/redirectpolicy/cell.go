// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/api/v1/server/restapi/service"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// Cell implements the processing of the CiliumLocalRedirectPolicy and
// CiliumClusterwideLocalRedirectPolicy CRDs.
// For each legacy policy it creates a pseudo-service with suffix -local-redirect
// and associates to it all matching local pods as backends. The service
// frontends that are being redirected will then take the backends of the
// pseudo-service.
var Cell = cell.Module(
	"local-redirect-policies",
	"Controller for CiliumLocalRedirectPolicy",

	ConfigCell,

	cell.Provide(
		// Provide Table[*LocalRedirectPolicy]. Used from replaceAPI.
		statedb.RWTable[*LocalRedirectPolicy].ToTable,
		// Provide Table[*ClusterwideLocalRedirectPolicy] for StateDB inspection.
		statedb.RWTable[*ClusterwideLocalRedirectPolicy].ToTable,
		// Provide Table[*ClusterwideLocalRedirectMapping] for frontend/backend
		// reconciliation and StateDB inspection.
		statedb.RWTable[*ClusterwideLocalRedirectMapping].ToTable,

		// Wait for the local redirect policy CRDs when LRP is enabled.
		lrpCRDSyncResourceNames,

		// Provide the [lbmap.SkipLBMap]. Provided globally to register it.
		newSkipLBMap,

		// Provide the 'skiplbmap' command for inspecting SkipLBMap.
		newSkipLBMapCommand,

		// Provide the 'lrp/list' command for inspecting the LRP REST API model.
		newLRPListCommand,
	),

	cell.ProvidePrivate(
		newLRPListerWatcher,
		newCCLRPListerWatcher,
		NewLRPTable,
		NewCCLRPTable,
		newCCLRPReflector,
		NewCCLRPMappingTable,
		newCCLRPMapper,
		newDesiredSkipLBTable,
	),

	cell.Invoke(
		// Reflect the CiliumLocalRedirectPolicy CRDs into Table[*LocalRedirectPolicy]
		registerLRPReflector,
		// Reflect CiliumClusterwideLocalRedirectPolicy CRDs into the normalised
		// CCLRP intent table.
		registerCCLRPReflector,

		// Resolve address-based CCLRP intent into concrete mappings.
		registerCCLRPMapper,

		// Register a controller to process the changes in the LRP, pod and frontend
		// tables.
		registerLRPController,

		// Register the SkipLBMap recnociler and the endpoint subscriber for pulling
		// pod netns cookies
		registerSkipLBReconciler,
	),

	metrics.Metric(newControllerMetrics),

	cell.Provide(lrpAPI),
)

// lrpCRDSyncResourceNames makes the agent wait for the local redirect policy
// CRDs to synchronise when LRP is enabled.
func lrpCRDSyncResourceNames(cfg Config) k8sSynced.CRDSyncResourceNamesOut {
	if !cfg.IsEnabled() {
		return k8sSynced.CRDSyncResourceNamesOut{}
	}
	return k8sSynced.NewCRDSyncResourceNamesOut(
		k8sSynced.CRDResourceName(ciliumv2.CLRPName),
		k8sSynced.CRDResourceName(ciliumv2.CCLRPName),
	)
}

func lrpAPI(
	db *statedb.DB,
	lrps statedb.Table[*LocalRedirectPolicy],
	frontends statedb.Table[*lb.Frontend],
	backends statedb.Table[*lb.Backend],
	pods statedb.Table[k8sTables.LocalPod],
) service.GetLrpHandler {
	return &getLrpHandler{
		db:        db,
		lrps:      lrps,
		frontends: frontends,
		backends:  backends,
		pods:      pods,
	}
}

type controllerMetrics struct {
	ControllerDuration metric.Histogram
}

func newControllerMetrics() controllerMetrics {
	return controllerMetrics{
		ControllerDuration: metric.NewHistogram(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: "localredirectpolicy",
			Name:      "controller_duration_seconds",
			Help:      "Histogram of LocalRedirectPolicy processing times",
			// Use buckets in the 0.5ms-1.0s range.
			Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, 0.1, 0.25, 0.5, 1.0},
		}),
	}
}

type LRPMetrics interface {
	AddLRPConfig(loadbalancer.ServiceName)
	DelLRPConfig(loadbalancer.ServiceName)
}

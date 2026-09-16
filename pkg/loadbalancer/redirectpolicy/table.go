// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"iter"
	"log/slog"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/client-go/tools/cache"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	LRPTableName   = "localredirectpolicies"
	CCLRPTableName = "localredirects"
)

var (
	lrpIDIndex = statedb.Index[*LocalRedirectPolicy, lb.ServiceName]{
		Name: "id",
		FromObject: func(obj *LocalRedirectPolicy) index.KeySet {
			return index.NewKeySet(index.String(obj.ID.String()))
		},
		FromKey: index.Stringer[lb.ServiceName],
		Unique:  true,
	}

	lrpServiceIndex = statedb.Index[*LocalRedirectPolicy, lb.ServiceName]{
		Name: "service",
		FromObject: func(lrp *LocalRedirectPolicy) index.KeySet {
			return index.NewKeySet(index.String(lrp.ServiceID.String()))
		},
		FromKey: index.Stringer[lb.ServiceName],
		Unique:  false,
	}

	lrpAddressIndex = statedb.Index[*LocalRedirectPolicy, lb.L3n4Addr]{
		Name: "address",
		FromObject: func(lrp *LocalRedirectPolicy) index.KeySet {
			if lrp.LRPType != lrpConfigTypeAddr {
				return index.KeySet{}
			}
			keys := make([]index.Key, 0, len(lrp.FrontendMappings))
			for _, feM := range lrp.FrontendMappings {
				keys = append(keys, feM.feAddr.Bytes())

			}
			return index.NewKeySet(keys...)
		},
		FromKey: func(addr lb.L3n4Addr) index.Key { return addr.Bytes() },
		Unique:  false,
	}
)

func NewLRPTable(db *statedb.DB) (statedb.RWTable[*LocalRedirectPolicy], error) {
	return statedb.NewTable(
		db,
		LRPTableName,
		lrpIDIndex,
		lrpServiceIndex,
		lrpAddressIndex,
	)
}

var (
	cclrpNameIndex = statedb.Index[*ClusterwideLocalRedirectPolicy, string]{
		Name: "name",
		FromObject: func(policy *ClusterwideLocalRedirectPolicy) index.KeySet {
			return index.NewKeySet(index.String(policy.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}

	cclrpServiceIndex = statedb.Index[*ClusterwideLocalRedirectPolicy, lb.ServiceName]{
		Name: "service",
		FromObject: func(policy *ClusterwideLocalRedirectPolicy) index.KeySet {
			if !policy.IsServiceMatcher() {
				return index.KeySet{}
			}
			return index.NewKeySet(policy.ServiceMatcher.Key())
		},
		FromKey: index.Stringer[lb.ServiceName],
		Unique:  false,
	}

	cclrpAddressIndex = statedb.Index[*ClusterwideLocalRedirectPolicy, cmtypes.AddrCluster]{
		Name: "address",
		FromObject: func(policy *ClusterwideLocalRedirectPolicy) index.KeySet {
			if !policy.IsAddressMatcher() {
				return index.KeySet{}
			}
			address := policy.AddressMatcher.As20()
			return index.NewKeySet(index.Key(address[:]))
		},
		FromKey: func(address cmtypes.AddrCluster) index.Key {
			key := address.As20()
			return index.Key(key[:])
		},
		Unique: false,
	}
)

// NewCCLRPTable creates the StateDB table containing normalised CCLRP intent.
func NewCCLRPTable(db *statedb.DB) (statedb.RWTable[*ClusterwideLocalRedirectPolicy], error) {
	return statedb.NewTable(
		db,
		CCLRPTableName,
		cclrpNameIndex,
		cclrpServiceIndex,
		cclrpAddressIndex,
	)
}

type lrpListerWatcher cache.ListerWatcher

func newLRPListerWatcher(cs client.Clientset) lrpListerWatcher {
	if !cs.IsEnabled() {
		return nil
	}
	return k8sUtils.ListerWatcherFromTyped(cs.CiliumV2().CiliumLocalRedirectPolicies("" /* all namespaces */))
}

func registerLRPReflector(cfg Config, db *statedb.DB, log *slog.Logger, jg job.Group, lw lrpListerWatcher, lrps statedb.RWTable[*LocalRedirectPolicy]) {
	if !cfg.IsEnabled() || lw == nil {
		return
	}

	k8s.RegisterReflector(jg, db,
		k8s.ReflectorConfig[*LocalRedirectPolicy]{
			Name:          "lrps",
			Table:         lrps,
			ListerWatcher: lw,
			MetricScope:   "CiliumLocalRedirectPolicy",
			TransformMany: func(_ statedb.ReadTxn, deleted bool, obj any) (toInsert, toDelete iter.Seq[*LocalRedirectPolicy]) {
				clrp := obj.(*ciliumv2.CiliumLocalRedirectPolicy)
				rp, err := parseLRP(cfg, log, clrp)
				if err != nil {
					log.Warn("Rejecting malformed CiliumLocalRedirectPolicy",
						logfields.K8sNamespace, clrp.Namespace,
						logfields.Name, clrp.Name,
						logfields.Error, err)
					toDelete = func(yield func(*LocalRedirectPolicy) bool) {
						yield(&LocalRedirectPolicy{
							ID:  lb.NewServiceName(clrp.Namespace, clrp.Name),
							UID: clrp.UID,
						})
					}
				} else {
					it := func(yield func(*LocalRedirectPolicy) bool) {
						yield(rp)
					}
					if deleted {
						toDelete = it
					} else {
						toInsert = it
					}
				}
				return
			},
		})
}

type cclrpListerWatcher cache.ListerWatcher

func newCCLRPListerWatcher(cs client.Clientset) cclrpListerWatcher {
	if !cs.IsEnabled() {
		return nil
	}
	return k8sUtils.ListerWatcherFromTyped(cs.CiliumV2().CiliumClusterwideLocalRedirectPolicies())
}

// cclrpReflector reflects Kubernetes CCLRP resources into the normalised
// localredirects table.
type cclrpReflector struct {
	cfg Config

	db *statedb.DB

	log *slog.Logger

	lw cclrpListerWatcher

	cclrps statedb.RWTable[*ClusterwideLocalRedirectPolicy]
}

func newCCLRPReflector(
	cfg Config,
	db *statedb.DB,
	log *slog.Logger,
	lw cclrpListerWatcher,
	cclrps statedb.RWTable[*ClusterwideLocalRedirectPolicy],
) *cclrpReflector {
	return &cclrpReflector{
		cfg:    cfg,
		db:     db,
		log:    log,
		lw:     lw,
		cclrps: cclrps,
	}
}

func registerCCLRPReflector(jg job.Group, reflector *cclrpReflector) {
	if !reflector.cfg.IsEnabled() || reflector.lw == nil {
		return
	}

	k8s.RegisterReflector(jg, reflector.db,
		k8s.ReflectorConfig[*ClusterwideLocalRedirectPolicy]{
			Name:          "cclrps",
			Table:         reflector.cclrps,
			ListerWatcher: reflector.lw,
			MetricScope:   "CiliumClusterwideLocalRedirectPolicy",
			TransformMany: func(_ statedb.ReadTxn, deleted bool, obj any) (toInsert, toDelete iter.Seq[*ClusterwideLocalRedirectPolicy]) {
				clrp := obj.(*ciliumv2.CiliumClusterwideLocalRedirectPolicy)
				policy, err := parseCCLRP(reflector.cfg, clrp)
				if err != nil {
					reflector.log.Warn("Rejecting malformed CiliumClusterwideLocalRedirectPolicy",
						logfields.Name, clrp.Name,
						logfields.Error, err)
					toDelete = func(yield func(*ClusterwideLocalRedirectPolicy) bool) {
						yield(&ClusterwideLocalRedirectPolicy{Name: clrp.Name, UID: clrp.UID})
					}
				} else {
					it := func(yield func(*ClusterwideLocalRedirectPolicy) bool) {
						yield(policy)
					}
					if deleted {
						toDelete = it
					} else {
						toInsert = it
					}
				}
				return
			},
		})
}

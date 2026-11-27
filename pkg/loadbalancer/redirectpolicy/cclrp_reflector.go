// This file was not reviewed by a human before submission
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"iter"
	"log/slog"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type cclrpListerWatcher cache.ListerWatcher

func newCCLRPListerWatcher(cs client.Clientset) cclrpListerWatcher {
	if !cs.IsEnabled() {
		return nil
	}
	return k8sUtils.ListerWatcherFromTyped(cs.CiliumV2alpha1().CiliumClusterwideLocalRedirectPolicies())
}

func registerCCLRPReflector(
	cfg Config,
	db *statedb.DB,
	log *slog.Logger,
	jg job.Group,
	lw cclrpListerWatcher,
	policies statedb.RWTable[*ClusterwideLocalRedirectPolicy],
) {
	if !cfg.IsEnabled() || lw == nil {
		return
	}

	k8s.RegisterReflector(jg, db, k8s.ReflectorConfig[*ClusterwideLocalRedirectPolicy]{
		Name:          "cclrps",
		Table:         policies,
		ListerWatcher: lw,
		MetricScope:   "CiliumClusterwideLocalRedirectPolicy",
		TransformMany: func(_ statedb.ReadTxn, deleted bool, obj any) (toInsert, toDelete iter.Seq[*ClusterwideLocalRedirectPolicy]) {
			clrp := obj.(*ciliumv2alpha1.CiliumClusterwideLocalRedirectPolicy)
			policy, err := parseCCLRP(clrp)
			if err != nil {
				log.Warn("Rejecting malformed CiliumClusterwideLocalRedirectPolicy",
					logfields.Name, clrp.Name,
					logfields.Error, err)
				toDelete = func(yield func(*ClusterwideLocalRedirectPolicy) bool) {
					yield(&ClusterwideLocalRedirectPolicy{Name: clrp.Name, UID: clrp.UID})
				}
				return
			}
			it := func(yield func(*ClusterwideLocalRedirectPolicy) bool) { yield(policy) }
			if deleted {
				toDelete = it
			} else {
				toInsert = it
			}
			return
		},
	})
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type noPoliciesExtra struct{}

func (t noPoliciesExtra) build(ct *check.ConnectivityTest, _ map[string]string) {
	scenarios := []check.Scenario{
		tests.PodToRemoteNodePort(),
		tests.PodToLocalNodePort(),
		tests.PodToLocalNodePortETPLocal(),
	}
	if ct.Params().ServiceType == "LoadBalancer" {
		scenarios = append(scenarios, tests.PodToLocalLoadBalancerETPLocal())
	}

	newTest("no-policies-extra", ct).
		WithFeatureRequirements(withKPRReqForMultiCluster(ct)...).
		WithScenarios(scenarios...)
}

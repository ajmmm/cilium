// This file was not reviewed by a human before submission
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

const (
	CCLRPTableName      = "clusterwidelocalredirectpolicies"
	CCLRPStateTableName = "clusterwidelocalredirectpolicy-state"
)

var (
	cclrpNameIndex = statedb.Index[*ClusterwideLocalRedirectPolicy, string]{
		Name: "name",
		FromObject: func(policy *ClusterwideLocalRedirectPolicy) index.KeySet {
			return index.NewKeySet(index.String(policy.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}

	cclrpStateNameIndex = statedb.Index[*ClusterwideLocalRedirectPolicyState, string]{
		Name: "name",
		FromObject: func(state *ClusterwideLocalRedirectPolicyState) index.KeySet {
			return index.NewKeySet(index.String(state.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}
)

func NewCCLRPTable(db *statedb.DB) (statedb.RWTable[*ClusterwideLocalRedirectPolicy], error) {
	return statedb.NewTable(db, CCLRPTableName, cclrpNameIndex)
}

func NewCCLRPStateTable(db *statedb.DB) (statedb.RWTable[*ClusterwideLocalRedirectPolicyState], error) {
	return statedb.NewTable(db, CCLRPStateTableName, cclrpStateNameIndex)
}

// ClusterwideLocalRedirectPolicyState is the computed per-node CCLRP plan.
// Service frontends remain owned by the load-balancer Writer and are not
// copied into this table; address matchers retain their configured address.
type ClusterwideLocalRedirectPolicyState struct {
	Name             string
	UID              string
	Generation       int64
	BackendNamespace string
	AddressMatcher   *netip.Addr
	ServiceMatcher   *lb.ServiceName
	Mappings         []ClusterwideLocalRedirectPolicyPortState
	Error            string
}

type ClusterwideLocalRedirectPolicyPortState struct {
	Port                 uint16
	TargetPort           uint16
	Protocol             lb.L4Type
	Backends             []lb.L3n4Addr
	MatchedFrontendCount int
	Error                string
}

func (state *ClusterwideLocalRedirectPolicyState) TableHeader() []string {
	return []string{"Name", "BackendNamespace", "Matcher", "Mappings", "Error"}
}

func (state *ClusterwideLocalRedirectPolicyState) TableRow() []string {
	matcher := ""
	switch {
	case state.AddressMatcher != nil:
		matcher = "address=" + state.AddressMatcher.String()
	case state.ServiceMatcher != nil:
		matcher = "service=" + state.ServiceMatcher.String()
	}
	mappings := make([]string, len(state.Mappings))
	for i, mapping := range state.Mappings {
		backendAddresses := make([]string, len(mapping.Backends))
		for j, backend := range mapping.Backends {
			backendAddresses[j] = backend.StringWithProtocol()
		}
		mappings[i] = fmt.Sprintf("%d->%d/%s backends=[%s] frontends=%d error=%s",
			mapping.Port, mapping.TargetPort, mapping.Protocol,
			strings.Join(backendAddresses, ", "), mapping.MatchedFrontendCount, mapping.Error)
	}
	return []string{
		state.Name,
		state.BackendNamespace,
		matcher,
		strings.Join(mappings, "; "),
		state.Error,
	}
}

var (
	_ statedb.TableWritable = (*ClusterwideLocalRedirectPolicy)(nil)
	_ statedb.TableWritable = (*ClusterwideLocalRedirectPolicyState)(nil)
)

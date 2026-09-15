// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"fmt"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/types"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

const CCLRPMappingTableName = "localredirectmappings"

// ClusterwideLocalRedirectMapping is a concrete mapping from a frontend
// address to a target port, derived from local redirect policy intent. Service
// matchers are added once their Service frontends have been resolved.
type ClusterwideLocalRedirectMapping struct {
	// PolicyName identifies the owning cluster-scoped local redirect policy.
	PolicyName string

	// PolicyUID is the unique identifier assigned by Kubernetes.
	PolicyUID types.UID

	// FrontendAddress is the concrete address and source port to match.
	FrontendAddress lb.L3n4Addr

	// TargetPort is the port and protocol on the selected local endpoint.
	TargetPort lb.L4Addr

	// Status reports whether this mapping has been applied to load-balancer state.
	Status reconciler.Status
}

func (mapping *ClusterwideLocalRedirectMapping) TableHeader() []string {
	return []string{
		"Policy",
		"FrontendAddress",
		"TargetPort",
		"Status",
		"Error",
	}
}

func (mapping *ClusterwideLocalRedirectMapping) TableRow() []string {
	return []string{
		mapping.PolicyName,
		mapping.FrontendAddress.StringWithProtocol(),
		mapping.TargetPort.String(),
		mapping.Status.Kind.String(),
		mapping.Status.GetError(),
	}
}

func (mapping *ClusterwideLocalRedirectMapping) id() string {
	return fmt.Sprintf("%s/%s", mapping.PolicyName, mapping.FrontendAddress.StringWithProtocol())
}

var (
	cclrpMappingIDIndex = statedb.Index[*ClusterwideLocalRedirectMapping, string]{
		Name: "id",
		FromObject: func(mapping *ClusterwideLocalRedirectMapping) index.KeySet {
			return index.NewKeySet(index.String(mapping.id()))
		},
		FromKey: index.String,
		Unique:  true,
	}

	cclrpMappingFrontendAddressIndex = statedb.Index[*ClusterwideLocalRedirectMapping, lb.L3n4Addr]{
		Name: "frontend-address",
		FromObject: func(mapping *ClusterwideLocalRedirectMapping) index.KeySet {
			return index.NewKeySet(mapping.FrontendAddress.Bytes())
		},
		FromKey: func(frontendAddress lb.L3n4Addr) index.Key {
			return frontendAddress.Bytes()
		},
		Unique: false,
	}

	cclrpMappingPolicyIndex = statedb.Index[*ClusterwideLocalRedirectMapping, string]{
		Name: "policy",
		FromObject: func(mapping *ClusterwideLocalRedirectMapping) index.KeySet {
			return index.NewKeySet(index.String(mapping.PolicyName))
		},
		FromKey: index.String,
		Unique:  false,
	}
)

// NewCCLRPMappingTable creates the StateDB table containing concrete
// local redirect frontend-to-target mappings.
func NewCCLRPMappingTable(db *statedb.DB) (statedb.RWTable[*ClusterwideLocalRedirectMapping], error) {
	return statedb.NewTable(
		db,
		CCLRPMappingTableName,
		cclrpMappingIDIndex,
		cclrpMappingFrontendAddressIndex,
		cclrpMappingPolicyIndex,
	)
}

var _ statedb.TableWritable = &ClusterwideLocalRedirectMapping{}

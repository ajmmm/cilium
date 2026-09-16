// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	"k8s.io/apimachinery/pkg/types"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/time"
)

const CCLRPMappingTableName = "localredirectmappings"

// frontendExists reports whether a frontend query returned at least one result.
func frontendExists(frontends iter.Seq2[*lb.Frontend, statedb.Revision]) bool {
	for range frontends {
		return true
	}
	return false
}

// isClaimed reports whether a non-error CCLRP mapping currently claims the
// frontend. The returned watch fires when the claim appears or disappears.
func (mapper *cclrpMapper) isClaimed(txn statedb.ReadTxn, frontend lb.L3n4Addr) (bool, <-chan struct{}) {
	mappings, watch := mapper.Mappings.ListWatch(txn, cclrpMappingFrontendAddressIndex.Query(frontend))
	for mapping := range mappings {
		if mapping.Status.Kind != reconciler.StatusKindError {
			return true, watch
		}
	}
	return false, watch
}

// addressFrontendConflicts reports whether a non-local-redirect frontend owns
// the address. Local-redirect frontends can be replaced by a CCLRP claim.
func addressFrontendConflicts(frontends iter.Seq2[*lb.Frontend, statedb.Revision]) bool {
	for frontend := range frontends {
		return frontend.Type != lb.SVCTypeLocalRedirect
	}
	return false
}

// isMappingCandidate reports whether a frontend can be resolved for a
// ServiceMatcher policy.
func isMappingCandidate(frontend *lb.Frontend) bool {
	return frontend.Type == lb.SVCTypeClusterIP
}

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

// hasEquivalentStatus reports whether other has a status that satisfies the
// mapper's desired status. Pending and Done are both equivalent for a
// non-error mapping: the CCLRP controller owns the transition from Pending to
// Done, and the mapper must not reset that transition on every pass. Error
// statuses are equivalent only when their messages are unchanged.
func (mapping *ClusterwideLocalRedirectMapping) hasEquivalentStatus(other *ClusterwideLocalRedirectMapping) bool {
	if mapping.Status.Kind == reconciler.StatusKindError {
		return other.Status.Kind == reconciler.StatusKindError &&
			other.Status.GetError() == mapping.Status.GetError()
	}
	return other.Status.Kind != reconciler.StatusKindError
}

// isEquivalentTo reports whether other already represents the desired mapping
// without requiring a StateDB write. StateDB writes are observable events, so
// reinserting an equivalent mapping would wake the CCLRP controller and could
// create a reconciliation cycle without changing the resulting datapath state.
func (mapping *ClusterwideLocalRedirectMapping) isEquivalentTo(other *ClusterwideLocalRedirectMapping) bool {
	return mapping.PolicyName == other.PolicyName &&
		mapping.PolicyUID == other.PolicyUID &&
		mapping.FrontendAddress == other.FrontendAddress &&
		mapping.TargetPort == other.TargetPort &&
		mapping.hasEquivalentStatus(other)
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

// cclrpMapper resolves normalised CCLRP intent into concrete mappings.
type cclrpMapper struct {
	Config Config

	Log *slog.Logger

	DB *statedb.DB

	Policies statedb.Table[*ClusterwideLocalRedirectPolicy]

	Frontends statedb.Table[*lb.Frontend]

	Backends statedb.Table[*lb.Backend]

	Mappings statedb.RWTable[*ClusterwideLocalRedirectMapping]
}

type cclrpMapperParams struct {
	cell.In

	Config Config

	Log *slog.Logger

	DB *statedb.DB

	Policies statedb.Table[*ClusterwideLocalRedirectPolicy]

	Frontends statedb.Table[*lb.Frontend]

	Backends statedb.Table[*lb.Backend]

	Mappings statedb.RWTable[*ClusterwideLocalRedirectMapping]
}

func newCCLRPMapper(params cclrpMapperParams) *cclrpMapper {
	return &cclrpMapper{
		Config:    params.Config,
		Log:       params.Log,
		DB:        params.DB,
		Policies:  params.Policies,
		Frontends: params.Frontends,
		Backends:  params.Backends,
		Mappings:  params.Mappings,
	}
}

func registerCCLRPMapper(g job.Group, mapper *cclrpMapper) {
	if !mapper.Config.IsEnabled() {
		return
	}
	g.Add(job.OneShot("cclrp-mapper", mapper.run))
}

func (mapper *cclrpMapper) run(ctx context.Context, health cell.Health) error {
	const waitTime = 100 * time.Millisecond
	const initializerName = "cclrp-mapping-controller"

	wtxn := mapper.DB.WriteTxn(mapper.Mappings)
	mappingsInit := mapper.Mappings.RegisterInitializer(wtxn, initializerName)
	wtxn.Commit()

	for {
		// Watch normalised CCLRP intent, load-balancer frontends, and Service
		// backends. Policy changes create or remove mappings, frontend changes
		// resolve address matchers, and backend changes refresh inherited
		// Service port-to-targetPort mappings.
		allWatches := statedb.NewWatchSet()
		wtxn := mapper.DB.WriteTxn(mapper.Mappings)

		_, policiesInitWatch := mapper.Policies.Initialized(wtxn)
		allWatches.Add(policiesInitWatch)
		_, frontendsInitWatch := mapper.Frontends.Initialized(wtxn)
		allWatches.Add(frontendsInitWatch)
		_, backendsInitWatch := mapper.Backends.Initialized(wtxn)
		allWatches.Add(backendsInitWatch)

		policies, policiesWatch := mapper.Policies.AllWatch(wtxn)
		allWatches.Add(policiesWatch)

		desiredMappings := map[string]*ClusterwideLocalRedirectMapping{}
		insertMapping := func(policy *ClusterwideLocalRedirectPolicy, frontend lb.L3n4Addr, port ClusterwideLocalRedirectPort) {
			mapping := &ClusterwideLocalRedirectMapping{
				PolicyName:      policy.Name,
				PolicyUID:       policy.UID,
				FrontendAddress: frontend,
				TargetPort: lb.L4Addr{
					Protocol: port.Protocol,
					Port:     port.TargetPort,
				},
				Status: reconciler.StatusPending(),
			}
			desiredMappings[mapping.id()] = mapping
		}

		for policy := range policies {
			if policy.IsAddressMatcher() {
				for _, port := range policy.Ports {
					frontend := lb.NewL3n4Addr(
						port.Protocol,
						*policy.AddressMatcher,
						port.Port,
						lb.ScopeExternal,
					)
					frontends, frontendsWatch := mapper.Frontends.ListWatch(wtxn, lb.FrontendByAddress(frontend))
					allWatches.Add(frontendsWatch)
					if addressFrontendConflicts(frontends) {
						continue
					}
					insertMapping(policy, frontend, port)
				}
				continue
			}

			if policy.IsServiceMatcher() {
				frontends, frontendsWatch := mapper.Frontends.ListWatch(wtxn, lb.FrontendByServiceName(*policy.ServiceMatcher))
				allWatches.Add(frontendsWatch)
				backends, backendsWatch := lb.ListBackendsByServiceName(wtxn, mapper.Backends, *policy.ServiceMatcher)
				allWatches.Add(backendsWatch)
				for frontend := range frontends {
					if !isMappingCandidate(frontend) {
						continue
					}
					if len(policy.Ports) == 0 {
						for backend := range backends {
							if !backend.Address.Compatible(frontend.Address) {
								continue
							}
							if frontend.PortName != "" && !slices.Contains(backend.PortNames, string(frontend.PortName)) {
								continue
							}
							port := ClusterwideLocalRedirectPort{
								Port:       frontend.ServicePort,
								TargetPort: backend.Address.Port(),
								Protocol:   backend.Address.Protocol(),
							}
							insertMapping(policy, frontend.Address, port)
							break
						}
						continue
					}
					for _, port := range policy.Ports {
						if frontend.ServicePort == port.Port && frontend.Address.Protocol() == port.Protocol {
							insertMapping(policy, frontend.Address, port)
						}
					}
				}
			}
		}
		cclrpMappingConflicts(desiredMappings)

		existingMappings := map[string]*ClusterwideLocalRedirectMapping{}
		for mapping := range mapper.Mappings.All(wtxn) {
			existingMappings[mapping.id()] = mapping
		}
		for mappingID, mapping := range desiredMappings {
			if existing, found := existingMappings[mappingID]; found {
				delete(existingMappings, mappingID)
				if mapping.isEquivalentTo(existing) {
					continue
				}
			}
			if _, _, err := mapper.Mappings.Insert(wtxn, mapping); err != nil {
				health.Degraded("Failed to insert CCLRP mapping", err)
				mapper.Log.Error("Failed to insert CCLRP mapping",
					"policy", mapping.PolicyName,
					"frontend-address", mapping.FrontendAddress,
					"error", err)
			}
		}
		for mapping := range existingMappings {
			mapper.Mappings.Delete(wtxn, existingMappings[mapping])
		}

		if (policiesInitWatch == nil || chanIsClosed(policiesInitWatch)) &&
			(frontendsInitWatch == nil || chanIsClosed(frontendsInitWatch)) {
			mappingsInit(wtxn)
		}
		wtxn.Commit()

		_, err := allWatches.Wait(ctx, waitTime)
		if err != nil {
			return err
		}
	}
}

// cclrpMappingConflicts marks mappings that claim the same concrete frontend
// from more than one policy as errors. Policies matching the same address or
// Service may coexist when their ports do not overlap.
func cclrpMappingConflicts(mappings map[string]*ClusterwideLocalRedirectMapping) {
	frontendAddressMappings := map[lb.L3n4Addr][]*ClusterwideLocalRedirectMapping{}
	for _, mapping := range mappings {
		frontendAddressMappings[mapping.FrontendAddress] = append(frontendAddressMappings[mapping.FrontendAddress], mapping)
	}

	for frontendAddress, mappings := range frontendAddressMappings {
		policyNames := map[string]struct{}{}
		for _, mapping := range mappings {
			policyNames[mapping.PolicyName] = struct{}{}
		}
		if len(policyNames) < 2 {
			continue
		}

		names := make([]string, 0, len(policyNames))
		for policyName := range policyNames {
			names = append(names, policyName)
		}
		slices.Sort(names)
		err := fmt.Errorf("frontend address %s is claimed by multiple CCLRPs: %s", frontendAddress.StringWithProtocol(), strings.Join(names, ", "))
		for _, mapping := range mappings {
			mapping.Status = reconciler.StatusError(err)
		}
	}
}

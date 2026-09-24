// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
)

func TestLookupFrontendByTuple(t *testing.T) {
	db := statedb.New()
	fes, err := NewFrontendsTable(DefaultConfig, db)
	require.NoError(t, err, "NewFrontendsTable")

	var addr L3n4Addr
	addr.ParseFromString("10.0.0.1:80/TCP")

	wtxn := db.WriteTxn(fes)
	fe := &Frontend{
		FrontendParams: FrontendParams{Address: addr},
	}
	fes.Insert(wtxn, fe)
	txn := wtxn.Commit()

	fe2, found := LookupFrontendByTuple(txn, fes, addr.AddrCluster(), addr.Protocol(), addr.Port(), addr.Scope())
	require.True(t, found)
	require.NotNil(t, fe2)
	require.Equal(t, fe, fe2)

	var addr2 L3n4Addr
	addr2.ParseFromString("10.0.0.2:80/TCP")
	fe2, found = LookupFrontendByTuple(txn, fes, addr2.AddrCluster(), addr2.Protocol(), addr2.Port(), addr2.Scope())
	require.False(t, found)
	require.Nil(t, fe2)
}

func TestIsWildcardCandidate(t *testing.T) {
	addr := cmtypes.AddrClusterFrom(netip.MustParseAddr("10.96.0.1"), 0)

	tests := []struct {
		name                 string
		svcType              SVCType
		scope                uint8
		externalClusterIP    bool
		expectWildcardParent bool
	}{
		{
			name:                 "cluster IP is not a candidate by default",
			svcType:              SVCTypeClusterIP,
			scope:                ScopeExternal,
			externalClusterIP:    false,
			expectWildcardParent: false,
		},
		{
			name:                 "external cluster IP is a candidate",
			svcType:              SVCTypeClusterIP,
			scope:                ScopeExternal,
			externalClusterIP:    true,
			expectWildcardParent: true,
		},
		{
			name:                 "external load balancer is a candidate",
			svcType:              SVCTypeLoadBalancer,
			scope:                ScopeExternal,
			externalClusterIP:    false,
			expectWildcardParent: true,
		},
		{
			name:                 "internal load balancer is not a candidate",
			svcType:              SVCTypeLoadBalancer,
			scope:                ScopeInternal,
			externalClusterIP:    true,
			expectWildcardParent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fe := &Frontend{FrontendParams: FrontendParams{
				Address: NewL3n4Addr(TCP, addr, 80, tt.scope),
				Type:    tt.svcType,
			}}
			require.Equal(t, tt.expectWildcardParent, IsWildcardCandidate(fe, tt.externalClusterIP))
		})
	}
}

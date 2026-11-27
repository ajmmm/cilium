// This file was not reviewed by a human before submission
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"context"
	"errors"
	"iter"
	"net/netip"
	"reflect"
	"testing"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/statedb"
)

type restoreSkipLBMap struct {
	ipv4   map[lbmaps.SkipLB4Key]struct{}
	ipv6   map[lbmaps.SkipLB6Key]struct{}
	addErr error
}

func newRestoreSkipLBMap() *restoreSkipLBMap {
	return &restoreSkipLBMap{
		ipv4: map[lbmaps.SkipLB4Key]struct{}{},
		ipv6: map[lbmaps.SkipLB6Key]struct{}{},
	}
}

func (m *restoreSkipLBMap) AddLB4(cookie uint64, ip netip.Addr, port uint16, protocol uint8) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.ipv4[lbmaps.SkipLB4Key{
		NetnsCookie: cookie,
		Address:     ip.As4(),
		Port:        port,
		Protocol:    protocol,
	}] = struct{}{}
	return nil
}

func (m *restoreSkipLBMap) AddLB6(cookie uint64, ip netip.Addr, port uint16, protocol uint8) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.ipv6[lbmaps.SkipLB6Key{
		NetnsCookie: cookie,
		Address:     ip.As16(),
		Port:        port,
		Protocol:    protocol,
	}] = struct{}{}
	return nil
}

func (m *restoreSkipLBMap) AllLB4() iter.Seq2[*lbmaps.SkipLB4Key, *lbmaps.SkipLB4Value] {
	return func(yield func(*lbmaps.SkipLB4Key, *lbmaps.SkipLB4Value) bool) {
		keys := make([]lbmaps.SkipLB4Key, 0, len(m.ipv4))
		for key := range m.ipv4 {
			keys = append(keys, key)
		}
		for _, key := range keys {
			if !yield(&key, &lbmaps.SkipLB4Value{}) {
				return
			}
		}
	}
}

func (m *restoreSkipLBMap) AllLB6() iter.Seq2[*lbmaps.SkipLB6Key, *lbmaps.SkipLB6Value] {
	return func(yield func(*lbmaps.SkipLB6Key, *lbmaps.SkipLB6Value) bool) {
		keys := make([]lbmaps.SkipLB6Key, 0, len(m.ipv6))
		for key := range m.ipv6 {
			keys = append(keys, key)
		}
		for _, key := range keys {
			if !yield(&key, &lbmaps.SkipLB6Value{}) {
				return
			}
		}
	}
}

func (m *restoreSkipLBMap) DeleteLB4(key *lbmaps.SkipLB4Key) error {
	if _, found := m.ipv4[*key]; !found {
		return errors.New("IPv4 key not found")
	}
	delete(m.ipv4, *key)
	return nil
}

func (m *restoreSkipLBMap) DeleteLB6(key *lbmaps.SkipLB6Key) error {
	if _, found := m.ipv6[*key]; !found {
		return errors.New("IPv6 key not found")
	}
	delete(m.ipv6, *key)
	return nil
}

var _ lbmaps.SkipLBMap = (*restoreSkipLBMap)(nil)

func TestSkipLBPruneMigratesLegacyAnyEntries(t *testing.T) {
	const cookie uint64 = 12345
	const port = 8080

	m := newRestoreSkipLBMap()
	v4 := netip.MustParseAddr("192.0.2.1")
	v6 := netip.MustParseAddr("2001:db8::1")
	m.ipv4[lbmaps.SkipLB4Key{NetnsCookie: cookie, Address: v4.As4(), Port: port}] = struct{}{}
	m.ipv6[lbmaps.SkipLB6Key{NetnsCookie: cookie, Address: v6.As16(), Port: port}] = struct{}{}
	// Existing exact-protocol keys that are no longer desired must also be pruned.
	m.ipv4[lbmaps.SkipLB4Key{NetnsCookie: cookie, Address: v4.As4(), Port: port, Protocol: 99}] = struct{}{}
	m.ipv6[lbmaps.SkipLB6Key{NetnsCookie: cookie, Address: v6.As16(), Port: port, Protocol: 99}] = struct{}{}

	protocols := make([]loadbalancer.L4Type, 0, len(loadbalancer.AllProtocols))
	for _, protocol := range loadbalancer.AllProtocols {
		protocols = append(protocols, protocol)
	}
	addrs := make([]loadbalancer.L3n4Addr, 0, len(protocols)*2)
	for _, protocol := range protocols {
		addrs = append(addrs,
			loadbalancer.NewL3n4Addr(protocol, types.MustParseAddrCluster(v4.String()), port, loadbalancer.ScopeExternal),
			loadbalancer.NewL3n4Addr(protocol, types.MustParseAddrCluster(v6.String()), port, loadbalancer.ScopeExternal),
		)
	}
	desired := &desiredSkipLB{
		NetnsCookie:              new(cookie),
		SkipRedirectForFrontends: map[loadbalancer.ServiceName][]loadbalancer.L3n4Addr{{}: addrs},
	}
	objs := func(yield func(*desiredSkipLB, statedb.Revision) bool) {
		yield(desired, 0)
	}

	if err := (&skiplbOps{m: m}).Prune(context.Background(), nil, objs); err != nil {
		t.Fatal(err)
	}

	want4 := map[lbmaps.SkipLB4Key]struct{}{}
	want6 := map[lbmaps.SkipLB6Key]struct{}{}
	for _, protocol := range protocols {
		protoNumber := uint8(loadbalancer.L4TypeAsProtocolNumber(protocol))
		want4[lbmaps.SkipLB4Key{NetnsCookie: cookie, Address: v4.As4(), Port: port, Protocol: protoNumber}] = struct{}{}
		want6[lbmaps.SkipLB6Key{NetnsCookie: cookie, Address: v6.As16(), Port: port, Protocol: protoNumber}] = struct{}{}
	}
	if !reflect.DeepEqual(m.ipv4, want4) {
		t.Fatalf("IPv4 map after migration = %#v, want %#v", m.ipv4, want4)
	}
	if !reflect.DeepEqual(m.ipv6, want6) {
		t.Fatalf("IPv6 map after migration = %#v, want %#v", m.ipv6, want6)
	}
}

func TestSkipLBPruneKeepsLegacyEntryWhenAliasInsertFails(t *testing.T) {
	const cookie uint64 = 12345
	const port = 8080
	v4 := netip.MustParseAddr("192.0.2.1")
	m := newRestoreSkipLBMap()
	m.addErr = errors.New("map update failed")
	legacy := lbmaps.SkipLB4Key{NetnsCookie: cookie, Address: v4.As4(), Port: port}
	m.ipv4[legacy] = struct{}{}
	desired := &desiredSkipLB{
		NetnsCookie: new(cookie),
		SkipRedirectForFrontends: map[loadbalancer.ServiceName][]loadbalancer.L3n4Addr{
			{}: {loadbalancer.NewL3n4Addr(loadbalancer.TCP, types.MustParseAddrCluster(v4.String()), port, loadbalancer.ScopeExternal)},
		},
	}
	objs := func(yield func(*desiredSkipLB, statedb.Revision) bool) { yield(desired, 0) }

	err := (&skiplbOps{m: m}).Prune(context.Background(), nil, objs)
	if err == nil {
		t.Fatal("Prune succeeded, want alias insertion error")
	}
	if _, found := m.ipv4[legacy]; !found {
		t.Fatal("legacy entry removed after alias insertion failed")
	}
}

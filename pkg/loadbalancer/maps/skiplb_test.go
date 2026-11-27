// This file was not reviewed by a human before submission
// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"net/netip"
	"testing"
	"unsafe"
)

func TestSkipLBKeysIncludeProtocolWithoutGrowing(t *testing.T) {
	tcp4 := NewSkipLB4Key(1, netip.MustParseAddr("192.0.2.1"), 80, 6)
	udp4 := NewSkipLB4Key(1, netip.MustParseAddr("192.0.2.1"), 80, 17)
	if *tcp4 == *udp4 {
		t.Fatal("IPv4 SkipLB keys with different protocols are equal")
	}
	if got := unsafe.Sizeof(*tcp4); got != 16 {
		t.Fatalf("IPv4 SkipLB key size = %d, want 16", got)
	}

	tcp6 := NewSkipLB6Key(1, netip.MustParseAddr("2001:db8::1"), 80, 6)
	udp6 := NewSkipLB6Key(1, netip.MustParseAddr("2001:db8::1"), 80, 17)
	if *tcp6 == *udp6 {
		t.Fatal("IPv6 SkipLB keys with different protocols are equal")
	}
	if got := unsafe.Sizeof(*tcp6); got != 32 {
		t.Fatalf("IPv6 SkipLB key size = %d, want 32", got)
	}
}

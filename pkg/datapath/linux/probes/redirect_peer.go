// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
)

// haveRedirectPeerFlag verifies that a BPF program will run the bpf_redirect_peer() with
// a specific flag at runtime. It is necessary to emit instructions for this to ensure
// the helper actually runs.
func haveRedirectPeerFlag(flags int32) error {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "redirect_peer_flag_probe",
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			// IfIndex 42 should be set in the redirect, but we should never
			// get to device lookup, so this should work fine.
			asm.Mov.Imm(asm.R1, 42),
			asm.Mov.Imm(asm.R2, flags),
			asm.FnRedirectPeer.Call(),
			asm.Return(),
		},
		License: "Apache-2.0",
	})
	if err != nil {
		return fmt.Errorf("loading bpf_redirect_peer flag probe: %w", err)
	}
	defer prog.Close()

	ret, err := prog.Run(&ebpf.RunOptions{
		Data:   make([]byte, 14), // ETH_HLEN
		Repeat: 1,
	})
	if err != nil {
		return fmt.Errorf("running bpf_redirect_peer flag probe: %w", err)
	}

	switch ret {
	case uint32(netlink.TC_ACT_REDIRECT):
		// Accepted
		return nil
	case uint32(netlink.TC_ACT_SHOT):
		// Rejected, convert to ErrNotSupported
		return ErrNotSupported
	default:
		return fmt.Errorf("unexpected bpf_redirect_peer flag probe return value: %d", ret)
	}
}

// HaveRedirectPeerEgress returns nil if bpf_redirect_peer supports BPF_F_EGRESS.
// This capability was introduced in kernel 7.3.
var HaveRedirectPeerEgress = sync.OnceValue(func() error {
	// At the time of writing, BPF_F_EGRESS hasn't appeared in the golang
	// runtime yet, so we'll need to declare this flag locally for now.
	const bpfFlagEgress = 1 << 1
	return haveRedirectPeerFlag(bpfFlagEgress)
})

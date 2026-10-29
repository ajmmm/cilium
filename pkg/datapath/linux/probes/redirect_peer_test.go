// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedHaveRedirectPeerEgress(t *testing.T) {
	testutils.PrivilegedTest(t)
	testutils.SkipOnOldKernel(t, "7.3", "bpf_redirect_peer(BPF_F_EGRESS)")
	require.NoError(t, HaveRedirectPeerEgress())
}

func TestPrivilegedRedirectPeerFlags(t *testing.T) {
	testutils.PrivilegedTest(t)
	testutils.SkipOnOldKernel(t, "5.10", "bpf_redirect_peer")
	require.NoError(t, haveRedirectPeerFlag(0))
}

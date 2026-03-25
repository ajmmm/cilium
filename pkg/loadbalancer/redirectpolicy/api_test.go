// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	ciliumapi "github.com/cilium/cilium/pkg/policy/api"
)

var (
	testNamespace      = "kube-system"
	testServiceName    = "kube-dns"
	testPolicyName     = "nodelocaldns"
	testPodName        = "node-local-dns"
	testPodLabelKey    = "k8s-app"
	testPodLabelValue  = "node-local-dns"
	testContainerName  = "node-cache"
	testFrontendTCP    = "dns-tcp"
	testFrontendUDP    = "dns"
	testFrontendTCPFE  = lb.FEPortName(testFrontendTCP)
	testFrontendUDPFE  = lb.FEPortName(testFrontendUDP)
	testFrontendAddr   = "10.96.0.10"
	testAddressLRPAddr = "169.254.20.10"
	testNodePortAddr   = "10.0.0.10"
	testBackendAddrV4  = "10.1.0.35"
	testBackendAddrV6  = "fd00:10:1::1cfc"
	testUnknownPodAddr = "10.1.0.99"
	testFrontendPort   = uint16(53)
	testBackendTCPPort = uint16(53)
	testBackendUDPPort = uint16(53)
)

func testBackendsSeq(bes ...*lb.Backend) lb.BackendsSeq2 {
	return lb.BackendsSeq2(func(yield func(*lb.Backend, statedb.Revision) bool) {
		for _, be := range bes {
			if !yield(be, 0) {
				return
			}
		}
	})
}

func testFrontend(ip string, port uint16, proto lb.L4Type, feType lb.SVCType, svcName lb.ServiceName, portName lb.FEPortName, redirectTo *lb.ServiceName, bes ...*lb.Backend) *lb.Frontend {
	return &lb.Frontend{
		FrontendParams: lb.FrontendParams{
			Address:     lb.NewL3n4Addr(proto, cmtypes.MustParseAddrCluster(ip), port, lb.ScopeExternal),
			Type:        feType,
			ServiceName: svcName,
			PortName:    portName,
			ServicePort: port,
		},
		Backends:   testBackendsSeq(bes...),
		RedirectTo: redirectTo,
	}
}

func testBackend(svcName lb.ServiceName, ip string, port uint16, proto lb.L4Type, portName string) *lb.Backend {
	be := &lb.Backend{
		ServiceName: svcName,
		Address:     lb.NewL3n4Addr(proto, cmtypes.MustParseAddrCluster(ip), port, lb.ScopeExternal),
		PortNames:   []string{portName},
		State:       lb.BackendStateActive,
	}
	be.SetSourcePriority(0)
	return be
}

func testReadyPod() k8sTables.LocalPod {
	return k8sTables.LocalPod{
		Pod: &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      testPodName,
				Namespace: testNamespace,
				Labels: map[string]string{
					testPodLabelKey: testPodLabelValue,
				},
			},
			Spec: slim_corev1.PodSpec{
				Containers: []slim_corev1.Container{
					{
						Name: testContainerName,
						Ports: []slim_corev1.ContainerPort{
							{Name: testFrontendTCP, ContainerPort: 53, Protocol: slim_corev1.ProtocolTCP},
							{Name: testFrontendUDP, ContainerPort: 53, Protocol: slim_corev1.ProtocolUDP},
						},
					},
				},
			},
			Status: slim_corev1.PodStatus{
				Conditions: []slim_corev1.PodCondition{
					{Type: slim_corev1.PodReady, Status: slim_corev1.ConditionTrue},
				},
				PodIPs: []slim_corev1.PodIP{
					{IP: testBackendAddrV4},
					{IP: testBackendAddrV6},
				},
			},
		},
	}
}

func TestGetModelServiceMatcherUsesResolvedFrontends(t *testing.T) {
	db := statedb.New()
	frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := lb.NewBackendsTable(db)
	require.NoError(t, err)
	pods, err := k8sTables.NewPodTable(db)
	require.NoError(t, err)

	lrp := testNodeLocalDNSLRP(t)
	lrpSvcName := lrp.RedirectServiceName()

	wtxn := db.WriteTxn(frontends, backends, pods)

	// Set up a matching node-local-dns pod selected by the LRP backend selector.
	_, _, err = pods.Insert(wtxn, testReadyPod())
	require.NoError(t, err)

	// Set up the pseudo-service backends that are resolved onto each frontend.
	insertBackend := func(ip string, port uint16, proto lb.L4Type, portName string) *lb.Backend {
		be := testBackend(lrp.RedirectServiceName(), ip, port, proto, portName)
		_, _, err = backends.Insert(wtxn, be)
		require.NoError(t, err)
		return be
	}
	tcpBackend := insertBackend(testBackendAddrV4, testBackendTCPPort, lb.TCP, testFrontendTCP)
	udpBackend := insertBackend(testBackendAddrV6, testBackendUDPPort, lb.UDP, testFrontendUDP)

	// Set up both ClusterIP and NodePort service frontends and verify that only
	// redirected ClusterIP frontends are returned by the API, each with the
	// backend subset selected by the LB writer.
	_, _, err = frontends.Insert(wtxn, testFrontend(testFrontendAddr, testFrontendPort, lb.TCP, lb.SVCTypeClusterIP, lrp.ServiceID, testFrontendTCPFE, &lrpSvcName, tcpBackend))
	require.NoError(t, err)
	_, _, err = frontends.Insert(wtxn, testFrontend(testFrontendAddr, testFrontendPort, lb.UDP, lb.SVCTypeClusterIP, lrp.ServiceID, testFrontendUDPFE, &lrpSvcName, udpBackend))
	require.NoError(t, err)
	_, _, err = frontends.Insert(wtxn, testFrontend(testNodePortAddr, testFrontendPort, lb.TCP, lb.SVCTypeNodePort, lrp.ServiceID, testFrontendTCPFE, nil))
	require.NoError(t, err)
	_, _, err = frontends.Insert(wtxn, testFrontend(testNodePortAddr, testFrontendPort, lb.UDP, lb.SVCTypeNodePort, lrp.ServiceID, testFrontendUDPFE, nil))
	require.NoError(t, err)

	// Commit all test objects before rendering the API model from StateDB.
	wtxn.Commit()

	// Render the API model and verify that only resolved ClusterIP frontends are shown.
	model := lrp.getModel(db.ReadTxn(), frontends, backends, pods)
	require.NotNil(t, model)
	require.Len(t, model.FrontendMappings, 2)

	gotByProtocol := map[string]*models.FrontendMapping{}
	for _, fe := range model.FrontendMappings {
		assert.Equal(t, testFrontendAddr, fe.FrontendAddress.IP)
		assert.Equal(t, testFrontendPort, fe.FrontendAddress.Port)
		gotByProtocol[fe.FrontendAddress.Protocol] = fe
	}
	assert.Contains(t, gotByProtocol, lb.TCP)
	assert.Contains(t, gotByProtocol, lb.UDP)

	tcpFrontend := gotByProtocol[lb.TCP]
	require.Len(t, tcpFrontend.Backends, 1)
	assert.Equal(t, testNamespace+"/"+testPodName, tcpFrontend.Backends[0].PodID)
	assert.Equal(t, testBackendAddrV4, *tcpFrontend.Backends[0].BackendAddress.IP)
	assert.Equal(t, testBackendTCPPort, tcpFrontend.Backends[0].BackendAddress.Port)
	assert.Equal(t, lb.TCP, tcpFrontend.Backends[0].BackendAddress.Protocol)

	udpFrontend := gotByProtocol[lb.UDP]
	require.Len(t, udpFrontend.Backends, 1)
	assert.Equal(t, testNamespace+"/"+testPodName, udpFrontend.Backends[0].PodID)
	assert.Equal(t, testBackendAddrV6, *udpFrontend.Backends[0].BackendAddress.IP)
	assert.Equal(t, testBackendUDPPort, udpFrontend.Backends[0].BackendAddress.Port)
	assert.Equal(t, lb.UDP, udpFrontend.Backends[0].BackendAddress.Protocol)

	for _, fe := range model.FrontendMappings {
		assert.NotEmpty(t, fe.FrontendAddress.IP)
		_, err := netip.ParseAddr(fe.FrontendAddress.IP)
		assert.NoError(t, err)
	}
}

func TestGetModelServiceMatcherWithoutRedirectedFrontend(t *testing.T) {
	db := statedb.New()
	frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := lb.NewBackendsTable(db)
	require.NoError(t, err)
	pods, err := k8sTables.NewPodTable(db)
	require.NoError(t, err)

	lrp := testNodeLocalDNSLRP(t)
	wtxn := db.WriteTxn(frontends)

	// Set up a matching service frontend that the controller has not redirected.
	_, _, err = frontends.Insert(wtxn, &lb.Frontend{
		FrontendParams: lb.FrontendParams{
			Address:     lb.NewL3n4Addr(lb.TCP, cmtypes.MustParseAddrCluster(testFrontendAddr), testFrontendPort, lb.ScopeExternal),
			Type:        lb.SVCTypeClusterIP,
			ServiceName: lrp.ServiceID,
			PortName:    testFrontendTCPFE,
			ServicePort: testFrontendPort,
		},
	})
	require.NoError(t, err)

	// Commit the frontend and verify that the API does not expose unresolved frontend state.
	wtxn.Commit()

	model := lrp.getModel(db.ReadTxn(), frontends, backends, pods)
	require.NotNil(t, model)
	assert.Empty(t, model.FrontendMappings)
}

func TestGetModelAddressMatcherUsesConfiguredFrontends(t *testing.T) {
	db := statedb.New()
	frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := lb.NewBackendsTable(db)
	require.NoError(t, err)
	pods, err := k8sTables.NewPodTable(db)
	require.NoError(t, err)

	lrp := testAddressLRP(t)

	wtxn := db.WriteTxn(backends, pods)
	_, _, err = pods.Insert(wtxn, testReadyPod())
	require.NoError(t, err)

	tcpBackend := testBackend(lrp.RedirectServiceName(), testBackendAddrV4, testBackendTCPPort, lb.TCP, testFrontendTCP)
	_, _, err = backends.Insert(wtxn, tcpBackend)
	require.NoError(t, err)
	udpBackend := testBackend(lrp.RedirectServiceName(), testBackendAddrV6, testBackendUDPPort, lb.UDP, testFrontendUDP)
	_, _, err = backends.Insert(wtxn, udpBackend)
	require.NoError(t, err)
	wtxn.Commit()

	model := lrp.getModel(db.ReadTxn(), frontends, backends, pods)
	require.NotNil(t, model)
	require.Len(t, model.FrontendMappings, 2)

	gotByProtocol := map[string]*models.FrontendMapping{}
	for _, fe := range model.FrontendMappings {
		assert.Equal(t, testAddressLRPAddr, fe.FrontendAddress.IP)
		assert.Equal(t, testFrontendPort, fe.FrontendAddress.Port)
		require.Len(t, fe.Backends, 2)
		gotByProtocol[fe.FrontendAddress.Protocol] = fe
	}

	assert.Contains(t, gotByProtocol, lb.TCP)
	assert.Contains(t, gotByProtocol, lb.UDP)
}

func TestGetModelServiceMatcherFiltersUnredirectedFrontends(t *testing.T) {
	db := statedb.New()
	frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := lb.NewBackendsTable(db)
	require.NoError(t, err)
	pods, err := k8sTables.NewPodTable(db)
	require.NoError(t, err)

	lrp := testNodeLocalDNSLRP(t)
	lrpSvcName := lrp.RedirectServiceName()
	otherSvcName := lb.NewServiceName(testNamespace, "other-local-redirect")
	matchingBackend := testBackend(lrpSvcName, testBackendAddrV4, testBackendTCPPort, lb.TCP, testFrontendTCP)

	wtxn := db.WriteTxn(frontends, pods)
	_, _, err = pods.Insert(wtxn, testReadyPod())
	require.NoError(t, err)

	testCases := []struct {
		name       string
		ip         string
		svcType    lb.SVCType
		redirectTo *lb.ServiceName
	}{
		{
			name:       "included ClusterIP redirected to LRP",
			ip:         testFrontendAddr,
			svcType:    lb.SVCTypeClusterIP,
			redirectTo: &lrpSvcName,
		},
		{
			name:    "excluded ClusterIP without redirect",
			ip:      "10.96.0.11",
			svcType: lb.SVCTypeClusterIP,
		},
		{
			name:       "excluded ClusterIP redirected elsewhere",
			ip:         "10.96.0.12",
			svcType:    lb.SVCTypeClusterIP,
			redirectTo: &otherSvcName,
		},
		{
			name:       "excluded NodePort redirected to LRP",
			ip:         testNodePortAddr,
			svcType:    lb.SVCTypeNodePort,
			redirectTo: &lrpSvcName,
		},
	}

	for _, tt := range testCases {
		_, _, err = frontends.Insert(wtxn, testFrontend(tt.ip, testFrontendPort, lb.TCP, tt.svcType, lrp.ServiceID, testFrontendTCPFE, tt.redirectTo, matchingBackend))
		require.NoError(t, err, tt.name)
	}
	wtxn.Commit()

	model := lrp.getModel(db.ReadTxn(), frontends, backends, pods)
	require.NotNil(t, model)
	require.Len(t, model.FrontendMappings, 1)
	assert.Equal(t, testFrontendAddr, model.FrontendMappings[0].FrontendAddress.IP)
}

func TestGetModelServiceMatcherUnknownPodBackend(t *testing.T) {
	db := statedb.New()
	frontends, err := lb.NewFrontendsTable(lb.DefaultConfig, db)
	require.NoError(t, err)
	backends, err := lb.NewBackendsTable(db)
	require.NoError(t, err)
	pods, err := k8sTables.NewPodTable(db)
	require.NoError(t, err)

	lrp := testNodeLocalDNSLRP(t)
	lrpSvcName := lrp.RedirectServiceName()
	unknownPodBackend := testBackend(lrpSvcName, testUnknownPodAddr, testBackendTCPPort, lb.TCP, testFrontendTCP)

	wtxn := db.WriteTxn(frontends, pods)
	_, _, err = pods.Insert(wtxn, testReadyPod())
	require.NoError(t, err)
	_, _, err = frontends.Insert(wtxn, testFrontend(testFrontendAddr, testFrontendPort, lb.TCP, lb.SVCTypeClusterIP, lrp.ServiceID, testFrontendTCPFE, &lrpSvcName, unknownPodBackend))
	require.NoError(t, err)
	wtxn.Commit()

	model := lrp.getModel(db.ReadTxn(), frontends, backends, pods)
	require.NotNil(t, model)
	require.Len(t, model.FrontendMappings, 1)
	require.Len(t, model.FrontendMappings[0].Backends, 1)
	assert.Equal(t, "unknown", model.FrontendMappings[0].Backends[0].PodID)
	assert.Equal(t, testUnknownPodAddr, *model.FrontendMappings[0].Backends[0].BackendAddress.IP)
}

func testNodeLocalDNSLRP(t *testing.T) *LocalRedirectPolicy {
	t.Helper()

	lrp, err := getSanitizedLocalRedirectPolicy(
		Config{},
		slog.Default(),
		testPolicyName,
		testNamespace,
		k8sTypes.UID("test-uid"),
		v2.CiliumLocalRedirectPolicySpec{
			RedirectFrontend: v2.RedirectFrontend{
				ServiceMatcher: &v2.ServiceInfo{
					Name:      testServiceName,
					Namespace: testNamespace,
					ToPorts: []v2.PortInfo{
						{Port: "53", Name: "tcp", Protocol: ciliumapi.ProtoTCP},
						{Port: "53", Name: "udp", Protocol: ciliumapi.ProtoUDP},
					},
				},
			},
			RedirectBackend: v2.RedirectBackend{
				LocalEndpointSelector: slim_metav1.LabelSelector{
					MatchLabels: map[string]string{
						testPodLabelKey: testPodLabelValue,
					},
				},
				ToPorts: []v2.PortInfo{
					{Port: "53", Name: testFrontendTCP, Protocol: ciliumapi.ProtoTCP},
					{Port: "53", Name: testFrontendUDP, Protocol: ciliumapi.ProtoUDP},
				},
			},
		},
	)
	require.NoError(t, err)
	return lrp
}

func testAddressLRP(t *testing.T) *LocalRedirectPolicy {
	t.Helper()

	lrp, err := getSanitizedLocalRedirectPolicy(
		Config{},
		slog.Default(),
		testPolicyName,
		testNamespace,
		k8sTypes.UID("test-uid"),
		v2.CiliumLocalRedirectPolicySpec{
			RedirectFrontend: v2.RedirectFrontend{
				AddressMatcher: &v2.Frontend{
					IP: testAddressLRPAddr,
					ToPorts: []v2.PortInfo{
						{Port: "53", Name: "tcp", Protocol: ciliumapi.ProtoTCP},
						{Port: "53", Name: "udp", Protocol: ciliumapi.ProtoUDP},
					},
				},
			},
			RedirectBackend: v2.RedirectBackend{
				LocalEndpointSelector: slim_metav1.LabelSelector{
					MatchLabels: map[string]string{
						testPodLabelKey: testPodLabelValue,
					},
				},
				ToPorts: []v2.PortInfo{
					{Port: "53", Name: testFrontendTCP, Protocol: ciliumapi.ProtoTCP},
					{Port: "53", Name: testFrontendUDP, Protocol: ciliumapi.ProtoUDP},
				},
			},
		},
	)
	require.NoError(t, err)
	return lrp
}

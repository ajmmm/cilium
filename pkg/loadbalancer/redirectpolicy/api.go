// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"iter"

	"github.com/cilium/statedb"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/server/restapi/service"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

type getLrpHandler struct {
	db        *statedb.DB
	lrps      statedb.Table[*LocalRedirectPolicy]
	frontends statedb.Table[*lb.Frontend]
	backends  statedb.Table[*lb.Backend]
	pods      statedb.Table[k8sTables.LocalPod]
}

func (h *getLrpHandler) Handle(params service.GetLrpParams) middleware.Responder {
	return service.NewGetLrpOK().WithPayload(getLRPs(h.db.ReadTxn(), h.lrps, h.frontends, h.backends, h.pods))
}

func getLRPs(txn statedb.ReadTxn, lrps statedb.Table[*LocalRedirectPolicy], frontends statedb.Table[*lb.Frontend], backends statedb.Table[*lb.Backend], pods statedb.Table[k8sTables.LocalPod]) []*models.LRPSpec {
	list := make([]*models.LRPSpec, 0, lrps.NumObjects(txn))
	for lrp := range lrps.All(txn) {
		list = append(list, lrp.getModel(txn, frontends, backends, pods))
	}
	return list
}

func (lrp *LocalRedirectPolicy) getModel(txn statedb.ReadTxn, frontends statedb.Table[*lb.Frontend], backends statedb.Table[*lb.Backend], pods statedb.Table[k8sTables.LocalPod]) *models.LRPSpec {
	if lrp == nil {
		return nil
	}

	var feType, lrpType string
	switch lrp.FrontendType {
	case frontendTypeUnknown:
		feType = "unknown"
	case svcFrontendAll:
		feType = "clusterIP + all svc ports"
	case svcFrontendNamedPorts:
		feType = "clusterIP + named ports"
	case svcFrontendSinglePort:
		feType = "clusterIP + port"
	case addrFrontendSinglePort:
		feType = "IP + port"
	case addrFrontendNamedPorts:
		feType = "IP + named ports"
	}

	switch lrp.LRPType {
	case lrpConfigTypeNone:
		lrpType = "none"
	case lrpConfigTypeAddr:
		lrpType = "addr"
	case lrpConfigTypeSvc:
		lrpType = "svc"
	}

	return &models.LRPSpec{
		UID:              string(lrp.UID),
		Name:             lrp.ID.Name(),
		Namespace:        lrp.ID.Namespace(),
		FrontendType:     feType,
		LrpType:          lrpType,
		ServiceID:        lrp.ServiceID.String(),
		FrontendMappings: lrp.getFrontendMappingModels(txn, frontends, backends, pods),
	}
}

func getPodIDByIP(txn statedb.ReadTxn, pods statedb.Table[k8sTables.LocalPod]) map[string]string {
	podIDByIP := map[string]string{}
	for pod := range pods.All(txn) {
		podID := pod.Namespace + "/" + pod.Name
		for _, podIP := range pod.Status.PodIPs {
			podIDByIP[podIP.IP] = podID
		}
	}
	return podIDByIP
}

func getBackendModels(podIDByIP map[string]string, bes iter.Seq2[*lb.Backend, statedb.Revision]) []*models.LRPBackend {
	beModels := []*models.LRPBackend{}
	if bes == nil {
		return beModels
	}

	appendBackendModel := func(podID string, beAddrStr *string, be *lb.Backend) {
		beAddrModel := &models.BackendAddress{
			IP:       beAddrStr,
			Port:     be.Address.Port(),
			Protocol: be.Address.Protocol(),
		}
		state, _ := be.State.String()
		beAddrModel.State = state

		beModels = append(beModels, &models.LRPBackend{
			PodID:          podID,
			BackendAddress: beAddrModel,
		})
	}

	for be := range bes {
		beAddrStr := be.Address.Addr().String()
		podID, found := podIDByIP[beAddrStr]
		if !found {
			podID = "unknown"
		}
		appendBackendModel(podID, &beAddrStr, be)
	}

	return beModels
}

func (lrp *LocalRedirectPolicy) getFrontendMappingModels(txn statedb.ReadTxn, frontends statedb.Table[*lb.Frontend], backends statedb.Table[*lb.Backend], pods statedb.Table[k8sTables.LocalPod]) []*models.FrontendMapping {
	podIDByIP := getPodIDByIP(txn, pods)

	switch lrp.LRPType {
	case lrpConfigTypeAddr:
		bes, _ := lb.ListBackendsByServiceName(txn, backends, lrp.RedirectServiceName())
		beModels := getBackendModels(podIDByIP, lb.PreferredBackendsByAddress(bes))

		feMappingModelArray := make([]*models.FrontendMapping, 0, len(lrp.FrontendMappings))
		for _, feM := range lrp.FrontendMappings {
			feMappingModel := feM.getModel()
			feMappingModel.Backends = beModels
			feMappingModelArray = append(feMappingModelArray, feMappingModel)
		}
		return feMappingModelArray

	case lrpConfigTypeSvc:
		feMappingModelArray := []*models.FrontendMapping{}
		appendFrontendMapping := func(fe *lb.Frontend, beModels []*models.LRPBackend) {
			feMappingModelArray = append(feMappingModelArray, &models.FrontendMapping{
				FrontendAddress: &models.FrontendAddress{
					IP:       fe.Address.AddrCluster().String(),
					Protocol: fe.Address.Protocol(),
					Port:     fe.Address.Port(),
				},
				Backends: beModels,
			})
		}

		lrpServiceName := lrp.RedirectServiceName()

		// Search for any redirected frontends
		for fe := range frontends.List(txn, lb.FrontendByServiceName(lrp.ServiceID)) {
			if fe.Type != lb.SVCTypeClusterIP {
				continue
			}
			if fe.RedirectTo == nil || !fe.RedirectTo.Equal(lrpServiceName) {
				continue
			}

			beModels := getBackendModels(podIDByIP, iter.Seq2[*lb.Backend, statedb.Revision](fe.Backends))
			appendFrontendMapping(fe, beModels)
		}
		return feMappingModelArray
	}

	return nil
}

func (feM *feMapping) getModel() *models.FrontendMapping {
	return &models.FrontendMapping{
		FrontendAddress: &models.FrontendAddress{
			IP:       feM.feAddr.AddrCluster().String(),
			Protocol: feM.feAddr.Protocol(),
			Port:     feM.feAddr.Port(),
		},
	}
}

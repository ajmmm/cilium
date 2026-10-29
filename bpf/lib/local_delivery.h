/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "identity.h"
#include "dbg.h"
#include "eps.h"
#include "l3.h"
#include "proxy.h"
#include "token_bucket.h"

DECLARE_CONFIG(bool, enable_netkit, "Use netkit devices for pods")

/* Global map to jump into policy enforcement of sending endpoint */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, POLICY_PROG_MAP_SIZE);
} cilium_egresscall_policy __section_maps_btf;

static __always_inline __must_check int
tail_call_egress_policy(struct __ctx_buff *ctx, __u16 endpoint_id)
{
	tail_call_dynamic(ctx, &cilium_egresscall_policy, endpoint_id);
	/* same issue as for the cilium_call_policy calls */
	return DROP_EP_NOT_READY;
}

/* Global map to jump into policy enforcement of receiving endpoint */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, POLICY_PROG_MAP_SIZE);
} cilium_call_policy __section_maps_btf;

static __always_inline __must_check int
tail_call_policy(struct __ctx_buff *ctx, __u16 endpoint_id)
{
	if (__builtin_constant_p(endpoint_id)) {
		tail_call_static(ctx, cilium_call_policy, endpoint_id);
	} else {
		tail_call_dynamic(ctx, &cilium_call_policy, endpoint_id);
	}

	/* When forwarding from a BPF program to some endpoint,
	 * there are inherent races that can result in the endpoint's
	 * policy program being unavailable (eg. if the endpoint is
	 * terminating).
	 */
	return DROP_EP_NOT_READY;
}

enum delivery_action {
	DELIVER_POLICY,
	DELIVER_STACK,
	DELIVER_ENDPOINT,
};

static __always_inline enum delivery_action
get_delivery_action(struct __ctx_buff *ctx, bool from_host,
		    bool from_tunnel __maybe_unused,
		    bool *use_redirect_peer)
{
	/* Default to ordinary redirection after policy enforcement. */
	*use_redirect_peer = false;

	/* Peer redirection requires BPF host routing and an ingress hook.
	 * Host delivery and L7-LB reinjection execute on egress hooks.
	 */
	if (CONFIG(enable_bpf_host_routing) && !from_host) {
		/* Netkit transmission clears ingress_ifindex and cannot use
		 * redirect_peer(0). Enforce policy before ordinary redirection,
		 * while the host proxy is still reachable.
		 */
		if (CONFIG(enable_netkit) &&
		    ctx_get_ingress_ifindex(ctx) == 0)
			return DELIVER_POLICY;

		/* Tell the policy program to use peer redirection for delivery. */
		*use_redirect_peer = true;

		/* Peer redirection bypasses cil_to_container(), so destination
		 * ingress policy must run through the tailcall first.
		 */
		return DELIVER_POLICY;
	}

	/* Without endpoint routes, enforce destination ingress policy
	 * through the tailcall before delivery.
	 */
	if (!CONFIG(enable_endpoint_routes))
		return DELIVER_POLICY;

	/* Ordinary Netkit redirection also needs policy before the namespace
	 * switch, so L7 processing can still reach the host proxy.
	 */
	if (CONFIG(enable_netkit) && ctx_get_ingress_ifindex(ctx) == 0)
		return DELIVER_POLICY;

#ifndef ENABLE_NODEPORT
	/* Tunnel traffic using kube-proxy must traverse the stack for
	 * conntrack and reverse DNAT.
	 */
	if (from_tunnel)
		return DELIVER_STACK;
#endif

	/* Endpoint routes allow ordinary redirection to defer destination
	 * ingress policy to cil_to_container().
	 */
	return DELIVER_ENDPOINT;
}

static __always_inline int redirect_ep(struct __ctx_buff *ctx,
				       int ifindex,
				       bool use_redirect_peer,
				       bool from_tunnel)
{
	/* Plain redirection traverses cil_to_container() when it is attached. */
	if (!use_redirect_peer)
		return (int)ctx_redirect(ctx, ifindex, 0);

	/* When coming from overlay, we need to set packet type
	 * to HOST as otherwise we might get dropped in IP layer.
	 */
	if (from_tunnel)
		ctx_change_type(ctx, PACKET_HOST);

	/* Peer ingress bypasses the endpoint's transmit path and to-container hook. */
	return ctx_redirect_peer(ctx, ifindex, 0);
}

/* Defines the calling convention for bpf_lxc's ingress policy tail-call.
 * Note that skb->tc_index is also passed through.
 *
 * As the callers (from-overlay, from-netdev, ...) are re-generated independently
 * from the policy tail-call of the individual endpoints, any change to this code
 * needs to be introduced with compatibility in mind.
 */
static __always_inline void
local_delivery_fill_meta(struct __ctx_buff *ctx, __u32 seclabel,
			 bool delivery_redirect, bool use_redirect_peer,
			 bool from_host, bool from_tunnel, __u32 cluster_id)
{
	__u32 delivery_flags = 0;

	if (delivery_redirect)
		delivery_flags |= CB_DELIVERY_FLAGS_REDIRECT;
	if (use_redirect_peer)
		delivery_flags |= CB_DELIVERY_FLAGS_USE_REDIRECT_PEER;
	if (from_host)
		delivery_flags |= CB_DELIVERY_FLAGS_FROM_HOST;
	if (from_tunnel)
		delivery_flags |= CB_DELIVERY_FLAGS_FROM_TUNNEL;
	if (tc_index_from_ingress_proxy(ctx))
		delivery_flags |= CB_DELIVERY_FLAGS_FROM_INGRESS_PROXY;
	if (tc_index_from_egress_proxy(ctx))
		delivery_flags |= CB_DELIVERY_FLAGS_FROM_EGRESS_PROXY;

	ctx_store_meta(ctx, CB_SRC_LABEL, seclabel);
	ctx_store_meta(ctx, CB_DELIVERY_FLAGS, delivery_flags);
	ctx_store_meta(ctx, CB_CLUSTER_ID_INGRESS, cluster_id);
}

static __always_inline int
local_delivery(struct __ctx_buff *ctx, __u32 seclabel, __u32 magic,
	       const struct endpoint_info *ep, __u8 direction, bool from_host,
	       bool from_tunnel, __u32 cluster_id)
{
	enum delivery_action action;
	bool use_redirect_peer;

#if defined(IS_BPF_LXC) || defined(IS_BPF_HOST)
	/*
	 * Special LXC case for updating egress forwarding metrics.
	 * Note that the packet could still be dropped but it would show up
	 * as an ingress drop counter in metrics.
	 */
	update_metrics(ctx_full_len(ctx), direction, REASON_FORWARDED);
#endif

	if (direction == METRIC_INGRESS && !from_host) {
		/*
		 * Traffic from nodes, local endpoints, or hairpin connections is ignored
		 */
		int ret;

		ret = accept(ctx, ep->lxc_id);
		if (IS_ERR(ret))
			return ret;
	}

	action = get_delivery_action(ctx, from_host, from_tunnel, &use_redirect_peer);
	switch (action) {
	case DELIVER_STACK:
		set_identity_mark(ctx, seclabel, magic);
		/* The stack requires PACKET_HOST despite the endpoint MAC addresses. */
		ctx_change_type(ctx, PACKET_HOST);
		return CTX_ACT_OK;
	case DELIVER_ENDPOINT:
		/* Defer ingress policy to cil_to_container(). */
		set_identity_mark(ctx, seclabel, magic);
		return redirect_ep(ctx, ep->ifindex, false, from_tunnel);
	default:
		break;
	}

	/* Enforce destination ingress policy here when endpoint routes are off,
	 * when peer redirection bypasses cil_to_container(), or when Netkit needs
	 * proxy access before the namespace switch.
	 */
	local_delivery_fill_meta(ctx, seclabel, true, use_redirect_peer,
				 from_host, from_tunnel, cluster_id);
	return tail_call_policy(ctx, ep->lxc_id);
}

/* Performs IPv6 L2/L3 handling and delivers the packet to the destination pod
 * on the same node, either via the stack or via a redirect call.
 * Depending on the configuration, it may also enforce ingress policies for the
 * destination pod via a tail call.
 */
static __always_inline int ipv6_local_delivery(struct __ctx_buff *ctx, int l3_off,
					       __u32 seclabel, __u32 magic,
					       const struct endpoint_info *ep,
					       __u8 direction, bool from_host,
					       bool from_tunnel)
{
	int ret;

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, ep->lxc_id, seclabel);

	ret = ipv6_l3(ctx, l3_off, ep->node_mac.addr, ep->mac.addr, direction);
	if (ret != CTX_ACT_OK)
		return ret;

	return local_delivery(ctx, seclabel, magic, ep, direction, from_host,
			      from_tunnel, 0);
}

/* Performs IPv4 L2/L3 handling and delivers the packet to the destination pod
 * on the same node, either via the stack or via a redirect call.
 * Depending on the configuration, it may also enforce ingress policies for the
 * destination pod via a tail call.
 */
static __always_inline int ipv4_local_delivery(struct __ctx_buff *ctx, int l3_off,
					       __u32 seclabel, __u32 magic,
					       struct iphdr *ip4,
					       const struct endpoint_info *ep,
					       __u8 direction, bool from_host,
					       bool from_tunnel, __u32 cluster_id)
{
	int ret;

	cilium_dbg(ctx, DBG_LOCAL_DELIVERY, ep->lxc_id, seclabel);

	ret = ipv4_l3(ctx, l3_off, ep->node_mac.addr, ep->mac.addr, ip4);
	if (ret != CTX_ACT_OK)
		return ret;

	return local_delivery(ctx, seclabel, magic, ep, direction, from_host,
			      from_tunnel, cluster_id);
}

/* Performs IPv6 L2/L3 handling and delivers the packet to the cilium_host@ingress
 * interface on the same node via a redirect call.
 * If needed by the configuration, host policies will be enforced once delivered,
 * specifically in the cil_to_host program (cilium_host@ingress).
 */
static __always_inline int ipv6_host_delivery(struct __ctx_buff *ctx, int l3_off)
{
	union macaddr router_mac = CONFIG(interface_mac);
	union macaddr host_mac = CONFIG(cilium_host_mac);
	int ret;

	ret = ipv6_l3(ctx, l3_off, (__u8 *)&router_mac.addr, (__u8 *)&host_mac.addr, METRIC_INGRESS);
	if (ret != CTX_ACT_OK)
		return ret;

	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, CONFIG(cilium_host_ifindex));
	return ctx_redirect(ctx, CONFIG(cilium_host_ifindex), BPF_F_INGRESS);
}

/* Performs IPv4 L2/L3 handling and delivers the packet to the cilium_host@ingress
 * interface on the same node via a redirect call.
 * If needed by the configuration, host policies will be enforced once delivered,
 * specifically in the cil_to_host program (cilium_host@ingress).
 */
static __always_inline int ipv4_host_delivery(struct __ctx_buff *ctx, int l3_off, struct iphdr *ip4)
{
	union macaddr router_mac = CONFIG(interface_mac);
	union macaddr host_mac = CONFIG(cilium_host_mac);
	int ret;

	ret = ipv4_l3(ctx, l3_off, (__u8 *)&router_mac.addr, (__u8 *)&host_mac.addr, ip4);
	if (ret != CTX_ACT_OK)
		return ret;

	cilium_dbg_capture(ctx, DBG_CAPTURE_DELIVERY, CONFIG(cilium_host_ifindex));
	return ctx_redirect(ctx, CONFIG(cilium_host_ifindex), BPF_F_INGRESS);
}

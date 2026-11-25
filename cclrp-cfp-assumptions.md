<!-- This file was not reviewed by a human before submission -->

# CCLRP PoC assumptions

This document records assumptions for the second CiliumClusterwideLocalRedirectPolicy (CCLRP) prototype. They are working constraints for the PoC, not resolutions of the CFP's open questions or a claim that the CFP is ready for review.

## API and datapath assumptions

1. **Backend namespace is explicit.** A policy must identify the namespace from which backend pods are selected. The PoC will not rely on a namespace label in a cluster-wide pod selector to provide this boundary.
2. **Port mappings are explicit.** Each redirect must specify the frontend port, backend target port, and protocol. The PoC will not inherit all-port behavior or infer mappings from port names or Pod container-port declarations.
3. **One address per `addressMatcher`.** A matcher identifies one IP address. Policies that need both IPv4 and IPv6 use separate address matchers.
4. **Skip-map matching is protocol-aware.** The PoC distinguishes transport protocols when matching redirect frontends. The existing protocol-neutral skip-map behavior is treated as a legacy implementation detail, not a constraint for CCLRP.

## Status assumptions for the PoC

5. **Policy acceptance is cluster-wide; reconciliation errors are node-local.** The operator owns the policy-level `Accepted` condition. Agents report only local reconciliation failures, with each agent updating its own node entry. An agent clears its entry after successfully reconciling the current generation.
6. **No cluster-wide `Ready` condition.** Failure-only node reports cannot prove that all nodes have reconciled the current generation. The absence of an error therefore does not mean that every node is ready.
7. **Status volume needs validation.** Identical failures should be coalesced, and writes should be rate-limited. The PoC should make it possible to evaluate burst behavior, stale-generation handling, and removal of reports for deleted nodes. Those mechanics remain open for peer discussion.

These status assumptions guide the prototype and do not settle the CFP's status contract. The CFP's open questions remain unchanged until discussed with peers.

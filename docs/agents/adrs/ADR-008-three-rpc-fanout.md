# ADR-008: Three-Node RPC Fanout — Ports 8545 / 8547 / 8549, WS 8546 / 8548 / 8550

- **Status**: accepted
- **Date**: 2026-05-13
- **Authors**: shell-chain core (distilled by AI agent)
- **Related**: `workspace/ops/shell-chain-testnet/DEPLOYMENT-RUNBOOK.md`; ADR-009; CONSTITUTION audit P-7

## Context

The SG public testnet runs three validator nodes (`shell-node1`, `shell-node2`,
`shell-node3`) on a single host (SG3). Each node runs a full JSON-RPC HTTP
server and WebSocket server. All three share the same external IP; they are
differentiated only by port. Clients (explorer, faucet, `shell-stress`, CI
tools) need to send transactions and read chain state without a single point of
failure.

Design constraints:
- Each node process binds an internal `--rpc-addr 127.0.0.1:<port>` for HTTP
  JSON-RPC; the internal port is always `8545` relative to the node's config
  but the host-level port is unique per node.
- WS is enabled at `--ws --ws-port <port>`.
- The nginx reverse proxy on the host manages TLS termination and public-facing
  routing.
- `shell-stress` runs 64 workers at 25–31 TPS fanned out across all three
  nodes; this requires the client to know all RPC URLs at startup.

## Decision

Assign fixed host ports to each node role:

| Node | Role | HTTP RPC | WS | P2P | Metrics |
|---|---|---|---|---|---|
| `shell-node1` | validator-prover | `8545` | `8546` | `30303` | `9090` |
| `shell-node2` | validator | `8547` | `8548` | `30304` | `9091` |
| `shell-node3` | prover (no block production) | `8549` | `8550` | `30305` | `9092` |

Clients fan out across `http://127.0.0.1:8545`, `http://127.0.0.1:8547`,
`http://127.0.0.1:8549` for load balancing and failover. The `shell-stress`
service reads `RPC_URLS="http://127.0.0.1:8545 http://127.0.0.1:8547 http://127.0.0.1:8549"`.

The nginx upstream block distributes load across all three with `shell-node1`
as the primary and `shell-node2`/`shell-node3` as backups (see nginx config in
`workspace/ops/shell-chain-testnet/nginx.conf`).

## Rationale

- **No single point of failure**: if one node process crashes or is being
  redeployed, the two remaining nodes continue to serve RPC without client
  reconfiguration. `shell-stress` handles transport errors per worker and
  retries against the next URL.
- **Predictable port layout**: fixed, role-annotated ports enable deterministic
  `preflight-node.sh` health checks, Prometheus scrape configs (`:9090`,
  `:9091`, `:9092`), and systemd unit restart logic without dynamic port
  discovery.
- **Consistent with systemd topology**: the three-node port layout is generated
  by `setup-systemd.sh` with `TOPOLOGY=three-validator`; no manual config is
  required after initial setup (see ADR-009).
- **nginx load-balancing**: the reverse proxy provides connection-level load
  distribution and TLS termination for external clients, while internal clients
  (faucet, explorer, stress) connect directly via localhost ports to avoid the
  extra hop.

## Alternatives considered

- **Single load balancer (e.g., HAProxy / nginx upstream with active health
  check)**: rejected as the only external entry point — adds an extra hop for
  internal clients (faucet, stress, explorer) running on the same host. Internal
  tools should connect directly to avoid the proxy overhead and the proxy itself
  becoming a single point of failure.
- **DNS round-robin**: assigns a single hostname to all three IPs. Rejected:
  DNS caching at OS / library level means a crashed node continues to receive
  requests for minutes. Not compatible with single-host deployment (all three
  nodes share the same IP).
- **Dynamic port assignment**: ports assigned at node startup from a pool.
  Rejected: makes systemd unit files, Prometheus scrape configs, nginx upstreams,
  and `shell-stress` `RPC_URLS` all dynamic; significantly increases operational
  complexity and configuration drift risk.

## Consequences

- **Positive**: RPC availability survives single-node crashes/redeployments;
  verified on SG3 during rolling `bump-v0.22.1` deployments.
- **Positive**: deterministic port layout simplifies health checks, metrics
  scraping, and log correlation (node identity is evident from the port).
- **Positive**: `shell-stress` fanout distributes tx load across all three nodes,
  reducing the risk of per-node mempool saturation.
- **Negative**: all three nodes on a single host means a host-level failure
  (OS crash, instance termination) takes down all three simultaneously. This is
  an accepted testnet constraint; mainnet deployment will use separate hosts.
- **Risks / mitigations**: port collisions if a fourth node is added without
  updating the topology. Mitigated: `preflight-node.sh` checks that the expected
  port is free before startup; `setup-systemd.sh` enforces the port layout via
  generated unit files.

## Implementation references

- Ops: `workspace/ops/shell-chain-testnet/DEPLOYMENT-RUNBOOK.md:294-296` — node
  topology table (role, ports, P2P, metrics)
- Ops: `workspace/ops/shell-chain-testnet/DEPLOYMENT-RUNBOOK.md:152,167,196` —
  `--rpc-addr` and `--ws-port` CLI flags per node
- Ops: `workspace/ops/shell-chain-testnet/DEPLOYMENT-RUNBOOK.md:346,364` —
  `RPC_URLS` environment variable for `shell-stress`
- Ops: `workspace/ops/shell-chain-testnet/nginx.conf:413-415` — nginx upstream
  with primary + backup nodes
- Ops: `workspace/ops/shell-chain-testnet/setup-systemd.sh` — generates systemd
  units with the three-node port layout
- Constitution: CONSTITUTION audit P-7 (Three-Node RPC Fanout port assignment)

## Revisit triggers

- A fourth validator node is added (e.g., for a four-validator topology),
  requiring ports 8551/8552 and a `setup-systemd.sh` topology update.
- The testnet migrates to a multi-host setup, making in-process fanout
  unnecessary and shifting load balancing to a dedicated L4/L7 load balancer.
- `shell-stress` moves to a dedicated stress-test host where direct localhost
  port access is unavailable.

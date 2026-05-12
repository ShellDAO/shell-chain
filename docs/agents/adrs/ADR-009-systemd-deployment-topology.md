# ADR-009: systemd + Preflight Deployment Topology for SG Public Testnet

- **Status**: accepted
- **Date**: 2026-05-13
- **Authors**: shell-chain core (distilled by AI agent)
- **Related**: `workspace/ops/shell-chain-testnet/DEPLOYMENT-RUNBOOK.md`; `setup-systemd.sh`; `preflight-node.sh`; ADR-008

## Context

Shell-Chain's first public testnet (SG genesis-1) was deployed using Docker
Compose (`workspace/ops/testnet/docker-compose.testnet.yml`). This caused
several operational problems:

- **Keystore password loss incident**: validator keystore passwords were stored
  in `/run/secrets/` (Docker secrets, backed by tmpfs). After an instance
  restart the tmpfs was cleared and all three validator nodes could not unlock
  their keystores. The chain froze permanently at block 5074 and required a
  genesis reset.
- **Single-container blast radius**: Docker Compose orchestrates all three nodes
  as a single unit; restarting Compose to update one binary takes down all
  validators simultaneously.
- **Binary cross-compilation complexity**: the Docker image build requires
  cross-compilation (Mac arm64 → Linux x86_64); `cargo zigbuild` had toolchain
  resolution conflicts with the Solana toolchain on the build host.
- **Restart / watchdog overhead**: Docker daemon is an additional process layer;
  systemd's native `Restart=on-failure` and `RestartSec` are sufficient for the
  shell-node binary and avoid the daemon dependency.

## Decision

The SG public testnet runs under **systemd + preflight topology**:

- `setup-systemd.sh` (with `TOPOLOGY=three-validator`) generates three systemd
  unit files: `shell-node1.service`, `shell-node2.service`, `shell-node3.service`.
- Each unit includes `ExecStartPre=/opt/shell/bin/preflight-node.sh <N>` which
  validates key prerequisites before the node process starts:
  - keystore file exists and password file is readable,
  - expected RPC port is free,
  - data directory is writable,
  - genesis hash matches expected value.
- Explorer, faucet, and `shell-stress` run as separate systemd units;
  `shell-stress.service` is configured with 64 workers, 25–31 random TPS, 20s
  epochs, and `RPC_URLS` fanned across ports 8545/8547/8549.
- Secrets (keystore passwords) are stored in `/opt/shell/secrets/` (persistent,
  `chmod 700`), **never** in tmpfs or `/run/secrets/`.
- Node binaries are built natively on the server at
  `/opt/shell-chain-src/worktree/` using `cargo build --release`; no
  cross-compilation is required.

The Docker Compose file (`workspace/ops/testnet/docker-compose.testnet.yml`) is
**retired to reference-only** status: it may be consulted for single-node local
testing but must not be used for SG testnet redeployment.

## Rationale

- **Persistent secrets**: `/opt/shell/secrets/` survives instance restarts;
  `/run/secrets/` (tmpfs) does not. Eliminating Docker secrets removes the
  vector that caused the genesis-1 freeze.
- **Per-node restart granularity**: `systemctl restart shell-node2` affects only
  node2; the other two nodes continue producing and finalising blocks. This is
  essential for rolling binary upgrades.
- **`preflight-node.sh` as a deploy gate**: by checking prerequisites before
  `ExecStart`, the preflight prevents the most common failure modes
  (wrong password, port conflict, stale `libp2p.key`) without requiring a
  manual pre-deploy checklist.
- **Native build**: building on the server eliminates cross-compilation failures
  and ensures the binary matches the server's exact toolchain version (pinned
  via `rust-toolchain.toml`).
- **systemd watchdog**: `Restart=on-failure` with `RestartSec` provides
  automatic recovery from process crashes; no additional process supervisor
  (supervisord, Docker) is needed.

## Alternatives considered

- **Docker Compose (status quo ante)**: rejected for production due to the
  keystore loss incident and the all-or-nothing restart granularity. Retained as
  reference-only for local single-node devnet (`./dev.sh up`).
- **Kubernetes / container orchestration**: appropriate for multi-region mainnet
  deployment; over-engineered for a single-host three-validator testnet. Rejected
  for the current phase.
- **Manual `nohup` / `screen` process management**: no automatic restart; no
  health-check gate. Rejected.

## Consequences

- **Positive**: no more keystore-loss incidents; persistent secrets survive
  instance reboots.
- **Positive**: rolling binary upgrades without full-cluster downtime; verified
  during `bump-v0.22.1` deployments on SG3.
- **Positive**: `preflight-node.sh` catches misconfiguration before it causes a
  live incident.
- **Positive**: native build on SG3 eliminates cross-compilation complexity.
- **Negative**: `setup-systemd.sh` must be re-run (or unit files manually
  updated) whenever CLI flags or port assignments change. Operational discipline
  required.
- **Negative**: Docker Compose reference files in `workspace/ops/testnet/` could
  confuse new operators into using the wrong deployment path. Mitigated by the
  explicit DEPLOYMENT-RUNBOOK.md warning.
- **Risks / mitigations**: if `/opt/shell/secrets/` is not backed up before a
  server wipe, keys are lost.   Mitigation: see DEPLOYMENT-RUNBOOK.md "Key Management" section
  mandates immediate `scp` backup of secrets + keystores to a local safe
  location after every key generation event.

## Implementation references

- Ops: `workspace/ops/shell-chain-testnet/setup-systemd.sh` — generates systemd unit files
- Ops: `workspace/ops/shell-chain-testnet/preflight-node.sh` — pre-start health gate
- Ops: `workspace/ops/shell-chain-testnet/DEPLOYMENT-RUNBOOK.md:99,141,179,211-214,294-296` —
  systemd topology table, unit template, preflight checklist
- Ops: `workspace/ops/testnet/docker-compose.testnet.yml` — reference-only legacy file
- CONSTITUTION: `workspace/README.md` current posture note: "SG public testnet
  runs on the systemd / preflight topology. Do not redeploy SG using the legacy
  Docker alpha compose files — they are reference-only now."

## Revisit triggers

- The testnet expands to multiple hosts or cloud regions; at that point
  Kubernetes or a managed container service becomes appropriate.
- The `shell-stress` service is extracted to a dedicated host, requiring a
  different deployment mechanism for the load generator.
- A new genesis is performed that requires a different topology (e.g., 5
  validators), necessitating a `setup-systemd.sh` topology update and a new
  `preflight-node.sh` validation profile.

# Testnet systemd deployment

These templates persist the low-resource validator settings used for small
testnet instances. They are intended for 2 vCPU / 4 GiB hosts and keep ordinary
validators from running local STARK proof work.

Install on a host:

```bash
id -u shellchain >/dev/null 2>&1 || sudo useradd --system --home /var/lib/shell-chain --shell /usr/sbin/nologin shellchain
sudo install -d -o shellchain -g shellchain /mnt/shell-data /opt/shell
sudo install -m 0755 shell-node-start.sh /usr/local/bin/shell-node-start.sh
sudo install -m 0644 shell-node.service /etc/systemd/system/shell-node.service
sudo install -m 0644 shell-node.env.example /etc/default/shell-node
sudo systemctl daemon-reload
sudo systemctl enable --now shell-node
```

Multi-validator hosts can also install the bounded liveness watchdog:

```bash
sudo install -m 0755 shell-cluster-watchdog.sh /usr/local/bin/shell-cluster-watchdog.sh
sudo install -m 0644 shell-cluster-watchdog.service /etc/systemd/system/shell-cluster-watchdog.service
sudo install -m 0644 shell-cluster-watchdog.timer /etc/systemd/system/shell-cluster-watchdog.timer
sudo install -m 0644 shell-cluster-watchdog.env.example /etc/default/shell-cluster-watchdog
sudo systemctl daemon-reload
sudo systemctl enable --now shell-cluster-watchdog.timer
```

The watchdog requires every configured validator to report production readiness,
waits for sustained unavailability before taking action, never restarts while a
reachable managed node reports active synchronization, and restarts only an
unready validator per recovery interval. Before a restart it pauses the configured
transaction worker, verifies that reachable validators have converged to the same
height, and resumes traffic only after the target is production-ready. The exit
trap also resumes the worker if recovery is interrupted. Inactive services use a
shorter failure threshold and cannot be hidden by an unrelated process responding
on the same health endpoint. Order services from lowest to highest voting weight
in the environment file. Set `SHELL_WATCHDOG_CONFLICTING_SERVICES` only for legacy
or mutually exclusive units that must never run beside the managed validators.

When a validator-prover is configured, the STARK circuit breaker disables proving
after an excessive pending-settlement gauge, rejection delta, or consecutive
guarded-endpoint failures. It intentionally
does not subtract generated and accepted counters: those counters are local to a
process and do not represent an in-flight queue during historical catch-up. The
watchdog preserves the previous environment file with a timestamp before changing
the role and uses the same guarded restart path.

Operational defaults:

- `SHELL_NODE_ROLE=validator`
- `SHELL_ENABLE_STARK_AGGREGATION=false`
- `SHELL_STATE_CACHE_SIZE_MB=32`
- `SHELL_RPC_RATE_LIMIT=50`
- `SHELL_RPC_ADDR=127.0.0.1:8545`
- `SHELL_MAX_IDLE_INTERVAL_SECS=600`
- optional `SHELL_EXPECTED_AUTHORITY=0x...` fail-fast check against the
  configured keystore
- `SHELL_BOOTNODES` accepts a comma-separated list. Use at least two reachable
  validators or sentry peers for multi-validator networks, and configure each
  validator with the other validators' public P2P addresses so recovery does not
  depend on one node restarting first.
- systemd `MemoryMax=1900M`, `CPUQuota=90%`, low IO priority, and slow restart
- optional cluster watchdog with synchronization-aware, traffic-quiesced,
  sequential recovery and a STARK prover circuit breaker

Use a separate larger instance for proving. On that host set
`SHELL_NODE_ROLE=validator-prover` or `SHELL_NODE_ROLE=prover`, set
`SHELL_ENABLE_STARK_AGGREGATION=true`, and raise the systemd memory/CPU limits
to match the instance size.

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

The watchdog requires sustained production unavailability before taking action,
never restarts while a reachable node reports active synchronization, and
restarts only one validator per recovery interval. Order services from lowest
to highest voting weight in the environment file.

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
- optional cluster watchdog with synchronization-aware, sequential recovery

Use a separate larger instance for proving. On that host set
`SHELL_NODE_ROLE=validator-prover` or `SHELL_NODE_ROLE=prover`, set
`SHELL_ENABLE_STARK_AGGREGATION=true`, and raise the systemd memory/CPU limits
to match the instance size.

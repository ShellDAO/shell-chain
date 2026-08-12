# Shell-Node CLI Automation Guide

> Covers non-interactive password handling, CI/CD integration, and scripting patterns for
> `shell-node` v0.27.4+.

---

## Table of Contents

1. [Password Input Methods](#1-password-input-methods)
2. [CI / GitHub Actions](#2-ci--github-actions)
3. [Docker / systemd](#3-docker--systemd)
4. [Batch Key Generation](#4-batch-key-generation)
5. [Transaction Scripting](#5-transaction-scripting)
6. [Security Guidelines](#6-security-guidelines)

---

## 1. Password Input Methods

`shell-node` supports three non-interactive password sources, checked in priority order:

| Priority | Method | Flag | Notes |
|----------|--------|------|-------|
| 1 (highest) | Password file | `--password-file <path>` | First non-empty line used |
| 2 | stdin | `--password-stdin` | Pipe a single line |
| 3 (lowest) | Environment variable | `--allow-env-password` | Reads `SHELL_KEYSTORE_PASSWORD` |
| fallback | Interactive prompt | _(none)_ | Reads from `/dev/tty`, blocked in non-TTY |

### 1.1 Password File

```bash
echo "my-secure-password" > /run/secrets/keystore-password
chmod 600 /run/secrets/keystore-password

shell-node --password-file /run/secrets/keystore-password key generate --output validator.json
```

### 1.2 stdin

```bash
echo "my-secure-password" | shell-node --password-stdin key generate --output validator.json
```

Or with a heredoc:

```bash
shell-node --password-stdin key generate --output validator.json <<< "my-secure-password"
```

### 1.3 Environment Variable (requires explicit opt-in)

```bash
export SHELL_KEYSTORE_PASSWORD="my-secure-password"
shell-node --allow-env-password key generate --output validator.json
```

> ⚠️ **Never** use the env-var method on shared or multi-tenant hosts. Use `--password-file`
> with a secrets manager or `--password-stdin` with a secret injected at runtime.

---

## 2. CI / GitHub Actions

### 2.1 Key generation in CI

```yaml
# .github/workflows/testnet.yml
jobs:
  generate-keys:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate validator keystore
        env:
          KEYSTORE_PASSWORD: ${{ secrets.KEYSTORE_PASSWORD }}
        run: |
          echo "$KEYSTORE_PASSWORD" | \
            shell-node --password-stdin key generate \
              --algorithm mldsa65 \
              --output ./infra/validator.json
```

### 2.2 Inspect keystore address without password

```bash
# Address is stored in cleartext in the keystore — no password needed.
shell-node key inspect ./infra/validator.json
```

### 2.3 Send a transaction in CI

```bash
echo "$KEYSTORE_PASSWORD" | \
  shell-node --password-stdin tx send \
    --keystore ./infra/sender.json \
    --to 0x<RECIPIENT_ADDRESS_64_HEX> \
    --value 1000000000000000000 \
    --rpc http://47.97.111.158/rpc
```

---

## 3. Docker / systemd

### 3.1 Docker Compose with a secrets file

```yaml
# docker-compose.yml
services:
  validator:
    image: shell-chain:0.27.4
    command:
      - shell-node
      - --password-file=/run/secrets/ks-password
      - run
      - --keystore=/data/validator.json
      - --rpc-addr=0.0.0.0:8545
      - --network=testnet
      - --db=rocksdb
    volumes:
      - ./data:/data
    secrets:
      - ks-password

secrets:
  ks-password:
    file: ./secrets/ks-password.txt
```

### 3.2 systemd unit with an environment file

For testnet validators, prefer the maintained templates in
`infra/testnet/systemd/` instead of writing a unit from scratch. They include
the low-resource validator defaults, slow restart policy, and systemd
CPU/memory/IO guardrails.

```bash
cd infra/testnet/systemd
id -u shellchain >/dev/null 2>&1 || sudo useradd --system --home /var/lib/shell-chain --shell /usr/sbin/nologin shellchain
sudo install -d -o shellchain -g shellchain /mnt/shell-data /opt/shell
sudo install -m 0755 shell-node-start.sh /usr/local/bin/shell-node-start.sh
sudo install -m 0644 shell-node.service /etc/systemd/system/shell-node.service
sudo install -m 0644 shell-node.env.example /etc/default/shell-node
sudo systemctl daemon-reload
sudo systemctl enable --now shell-node
```

Edit `/etc/default/shell-node` for the host-specific datadir, keystore, password
file, RPC CORS, and bootnodes. Keep the password file mode `0600`, and keep RPC
on loopback unless it is protected by a firewall or reverse proxy.

---

## 4. Batch Key Generation

Generate N keystores in a loop (e.g. for test accounts):

```bash
#!/usr/bin/env bash
set -euo pipefail

PASSWORD="test-password-42"
OUT_DIR="./test-accounts"
mkdir -p "$OUT_DIR"

for i in $(seq 1 10); do
    echo "$PASSWORD" | shell-node --password-stdin key generate \
        --algorithm dilithium3 \
        --output "$OUT_DIR/account-$i.json"
    addr=$(shell-node key inspect "$OUT_DIR/account-$i.json" | grep -oP '(?<=Address: ).*')
    echo "account-$i: $addr"
done
```

---

## 5. Transaction Scripting

### 5.1 Shell-SDK tx-spammer (recommended)

For high-volume testing, use `shell-sdk` directly with `ShellSigner`:

```js
// scripts/tx-spammer.mjs
import { ShellSigner } from 'shell-sdk';
import { readFileSync } from 'fs';

const ks = JSON.parse(readFileSync('./test-accounts/account-1.json', 'utf8'));
const signer = await ShellSigner.fromKeystore(ks, process.env.KEYSTORE_PASSWORD);

const rpcUrl = 'http://47.97.111.158/rpc';
// ... send transactions
```

### 5.2 Single transaction via CLI

```bash
PASSWORD_FILE=./secrets/ks-password

shell-node --password-file "$PASSWORD_FILE" tx send \
    --keystore ./account-1.json \
    --to 0x<RECIPIENT_ADDRESS_64_HEX> \
    --value 1000000000 \
    --rpc http://47.97.111.158/rpc
```

---

## 6. Security Guidelines

| Rule | Reason |
|------|--------|
| Never pass password as a CLI argument (`--password mypassword`) | Visible in `ps aux`, shell history, and process environment |
| Set password file permissions to `0600` | Prevents other users/processes from reading it |
| Use `--password-file` with a secrets manager in production | Docker Secrets, Vault, AWS SSM Parameter Store, etc. |
| Use `--allow-env-password` only in disposable CI environments | Env vars leak into child processes and crash dumps |
| Rotate keystores after testnet resets | Old keystores may have mismatched chain IDs |

---

## See Also

- [Node CLI Reference](node-cli.md)
- [Keystore Format Specification](keystore-format.md)
- [Testnet Operator Guide](TESTNET_OPERATOR_GUIDE.md)
- [Post-Quantum Crypto Guide](PQ_CRYPTO_GUIDE.md)

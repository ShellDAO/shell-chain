#!/bin/bash
set -euo pipefail

DATADIR="${DATADIR:-/data}"
SHARED="${SHARED:-/shared}"
BOOTNODE_FILE="${SHARED}/node1-bootnode.addr"
NODE_LOG="${DATADIR}/shell-node.log"

mkdir -p "$DATADIR" "$SHARED"

extract_bootnode_addr() {
    if [ ! -f "$NODE_LOG" ]; then
        return 1
    fi

    grep -Eo 'Listening on /ip4/[^ ]+/tcp/[0-9]+/p2p/[A-Za-z0-9]+' "$NODE_LOG" \
        | sed 's/^Listening on //' \
        | grep -v '^/ip4/127\.0\.0\.1/' \
        | tail -n 1
}

if [ "${GENESIS_CREATOR:-false}" = "true" ]; then
    # First node: start shell-node which auto-creates genesis.json,
    # then copy it plus the current libp2p bootnode address to the shared volume
    # for followers.
    rm -f "$BOOTNODE_FILE" "$NODE_LOG"
    shell-node run "$@" > >(tee -a "$NODE_LOG") 2>&1 &
    NODE_PID=$!

    # Forward signals to the shell-node process.
    trap "kill -TERM $NODE_PID 2>/dev/null" TERM INT

    # Wait for genesis.json and a non-loopback libp2p listen address to be
    # written by the node during startup.
    for i in $(seq 1 120); do
        if ! kill -0 "$NODE_PID" 2>/dev/null; then
            echo "ERROR: shell-node exited before publishing genesis and bootnode" >&2
            wait "$NODE_PID" || exit "$?"
            exit 1
        fi

        if [ -f "$DATADIR/genesis.json" ] && [ ! -f "$SHARED/genesis.json" ]; then
            cp "$DATADIR/genesis.json" "$SHARED/genesis.json"
            echo "✓ Genesis shared to $SHARED/genesis.json"
        fi

        if [ ! -s "$BOOTNODE_FILE" ]; then
            BOOTNODE_ADDR="$(extract_bootnode_addr || true)"
            if [ -n "${BOOTNODE_ADDR:-}" ]; then
                printf '%s\n' "$BOOTNODE_ADDR" > "$BOOTNODE_FILE"
                echo "✓ Bootnode shared to $BOOTNODE_FILE: $BOOTNODE_ADDR"
            fi
        fi

        if [ -f "$SHARED/genesis.json" ] && [ -s "$BOOTNODE_FILE" ]; then
            break
        fi

        sleep 0.5
    done

    if [ ! -f "$SHARED/genesis.json" ]; then
        echo "ERROR: failed to share genesis.json"
        kill -TERM "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
        exit 1
    fi

    if [ ! -s "$BOOTNODE_FILE" ]; then
        echo "ERROR: failed to publish node1 bootnode address"
        kill -TERM "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
        exit 1
    fi

    wait $NODE_PID
    exit $?
else
    # Follower node: wait for shared genesis and leader bootnode before starting.
    echo "Waiting for genesis.json from leader..."
    for i in $(seq 1 60); do
        if [ -f "$SHARED/genesis.json" ]; then
            cp "$SHARED/genesis.json" "$DATADIR/genesis.json"
            echo "✓ Genesis loaded from shared volume"
            break
        fi
        sleep 1
    done

    if [ ! -f "$DATADIR/genesis.json" ]; then
        echo "ERROR: genesis.json not found after 60s"
        exit 1
    fi

    echo "Waiting for node1 bootnode address..."
    for i in $(seq 1 60); do
        if [ -s "$BOOTNODE_FILE" ]; then
            BOOTNODE_ADDR="$(cat "$BOOTNODE_FILE")"
            echo "✓ Bootnode loaded from shared volume: $BOOTNODE_ADDR"
            exec shell-node run "$@" --bootnode "$BOOTNODE_ADDR"
        fi
        sleep 1
    done

    echo "ERROR: bootnode address not found after 60s"
    exit 1
fi

# Retention after historical body restoration

Status: accepted for unreleased node source.

## Context

A rolling follower can restart with pruned bodies and request historical data
from a retaining peer. Its body-pruning cursor has already advanced past those
blocks. Restoring bodies without revisiting that cursor leaves expired data
behind. Running pruning only on canonical commits also leaves that data behind
when the restarted chain stays idle.

## Decision

Restore a canonical body and rewind the existing body-pruning cursor in one
storage batch, within the authenticated body/witness overlay when applicable.
Rejected authentication and failed commits change neither body nor cursor.
Each non-archive prune pass rereads durable progress so active and reconstructed
pruners see restoration. Apply the same bounded, finalized-height body policy
after a historical response as after a canonical commit.

Do not expire bodies while isolated legacy witness replay or its requested
ancestor dependency is pending: that replay reads ancestor bodies from the base
store. Resume retention after authentication finishes. Archive mode remains a
no-op. No activation, schema, genesis or chain-identity change is needed.

## Validation

Storage regressions check unchanged-head expiry through active and reconstructed
pruners and atomic authentication/commit rejection. Node coverage protects a
pending replay dependency before expiring its restored body. Run
`tests/e2e/native-aa-registry.mjs --epoch-pruned-restart` with the prerequisites
in `docs/JSON_RPC_API.md` to check real two-node RocksDB import, state/body
pruning, four restarts, pending Registry changes and the final idle-head query.
The one-block window does not establish default-window or power-loss behavior.

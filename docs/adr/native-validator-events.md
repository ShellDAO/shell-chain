# Native validator membership events

Status: implemented behind an optional, default-off activation schedule.

## Problem

The system-contract guide specifies indexed ValidatorAdded and ValidatorRemoved
identifiers. Direct execution previously emitted only the signature topic and
truncated the member to 20 bytes in the data word. Native AA execution emitted
no membership log. Successful real governance transactions therefore changed
the set without satisfying the documented receipt and topic-filter interface.

## Decision

Introduce independent `native_validator_events_height`. Omission preserves old
execution exactly. At and after activation, both native entrypoints share one
encoder: native Registry emitter, existing event signature topic, complete
32-byte member topic, empty data. Only committed add/remove effects produce a
log. AA execution stages logs in inner-call order and discards them with the
batch on later failure; pending governance votes do not emit membership events.
Existing native operation gas charges are unchanged.

Receipt roots and blooms depend on log contents, so the new behavior must not
be enabled retroactively. Existing databases accept only future scheduling;
persisted schedules are immutable and snapshot imports require matching trusted
configuration before writes. Producers, importers and historical execution use
the executed block height, not the current tip, to select the format.

A global unversioned fix would invalidate historical receipts. Reusing the
previous log-emitter-address activation would also change already active blocks.
Changing the event signature to bytes32 would unnecessarily split subscription
identities; native addresses already occupy complete 32-byte identifiers.

## Verification and limits

Focused execution tests cover disabled, before, exact and after activation,
full native identities, legacy encoding, blooms and atomic rollback. Startup and
snapshot tests cover schedule persistence and mismatch rejection. The existing
Registry two-node script exercises both entries, topic filtering, receipt
agreement, historical replay and restart. Test-network activation and compatible
SDK publication remain separate deployment decisions. This change does not
alter governance voting semantics or add new AccountManager event signatures.

The idle-tip restart check also exposed a startup defect: the builder kept
genesis authorities until another block triggered Registry reload. Startup now
invokes the existing reload rule at the stored head. This covers epoch length
zero and heads on configured boundaries without activating pending changes
early. Recovery between boundaries in a nonzero epoch is covered separately by
[epoch authority recovery](epoch-authority-recovery.md) and the Registry
acceptance script's `--epoch-restart` mode.

# Canonical system reward sender history

Status: accepted for unreleased node source

## Problem

Reward records expose an authenticated `from` address and are documented as
first-class transactions. Address history promises sent and received records,
but the writer indexed only reward recipients. Updating new writes alone would
leave retained rewards missing after an upgrade.

## Decision

Use the existing forward and reverse address indexes for each system transaction's
sender and distinct recipient, including deletion during canonical rollback.
Before NodeBuilder returns a node for RPC startup, repair derived address metadata
from retained system records whose block hash matches the canonical height map.
Do not require transaction witnesses or rewrite block bodies, receipts or state.

Copy at most 128 key/value rows or about 4 MiB from each native store visit before
writing a batch, outside the iterator's lock. One oversized stored row can exceed
the byte target. On failure, partial derived batches may remain; retry idempotently
from the beginning and record completion only after every canonical row succeeds.
Bind completion to the canonical head, and advance that checkpoint in normal
canonical block batches. An unchanged head avoids repeat scans. An older writer
changing the head invalidates completion; remove noncanonical zero-origin entries
before rebuilding, while preserving genuine canonical user transfers to zero.

## Scope

This changes local derived metadata and query completeness. It changes no reward
hash, signed field, fee accounting, consensus rule or activation height. Recovery
requires retained canonical system records; it does not recreate deleted chain
data. Native backends bound iterator memory; a third-party KvStore using the
materializing default visitor must supply its own streaming implementation to
obtain that bound. Repair runs under exclusive startup ownership, not during RPC.

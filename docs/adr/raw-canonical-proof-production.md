# Resumable raw canonical sender-proof production

Status: accepted for unreleased node source.

## Context

The complete sender verifier and offline importer consume linked mathematical
certificates, while the background prover still generates an accumulator.
Requiring manually prepared component graphs leaves no complete raw-source
producer. A full ML-DSA matrix proof is expensive enough that a process restart
must preserve completed work without trusting cached success flags.

## Decision

Add an explicit offline producer over a retained trusted canonical block.
Capture the body, configuration, parent account witnesses and registry keys from
the sealed native view. Native preflight refuses invalid signatures before
expensive generation; only the complete AIR verifier authenticates the output.
Keep the source database exclusively open and prohibit source/output overlap.
Automatic scheduling is specified separately in
[Automatic canonical production](automatic-canonical-proof-production.md).

Compose the existing mathematical proving functions and persist each completed,
verified certificate in a separate native job database. Atomically publish its
bytes, hash and quota accounting. Bind the job to the exact serialized public
source. Refuse corruption and unknown records rather than deleting or replacing
them. Reverify cached certificates against their exact inputs before reuse.
A nonzero component budget pauses with a nonzero exit and no completed artifact.

Bound logical checkpoint payload to 256 MiB and final artifact bytes separately
to the existing 256 MiB manifest limit; metadata/backend overhead is additional.
The final output is serialized with a bounded writer and reverified in full.
Publish immutable matching prefixes by append, sync files and their directory,
and refuse conflicting or linked files. Partial files and progress metadata
never construct a verified token. Preserve all wire limits, ordinary importer
checks, activation rules, native fees, settlement and pruning behavior.

## Validation

The public `mldsa-produce-proof` regression creates fresh funded test accounts,
a real signed canonical block and an independent parent-only follower. It cold
proves, pauses, reopens, resumes, imports the output through the actual CLI and
rechecks persisted execution with full proof-backed historical replay. Focused
store and file tests cover source/certificate mismatch, refusal before publishing,
quota, immutable cached bytes and conflicting output prefixes. The automatic producer has a separate runtime regression; ordinary automatic
peer admission, fork/amendment use and compact graphs remain separate
acceptance work; this source feature is not a network activation or release.

# Prover priority with ordered settlement

Status: accepted; unreleased implementation.

The prover guide offers latest-first computation, while strict settlement requires
contiguous source ranges in canonical order. Reversing publication would generate
work that cannot be accepted at the current frontier. Merely reversing concurrent
spawn calls would not establish an observable priority with a single worker.

Latest-first therefore reserves a contiguous window of at most twice the configured
worker limit. A bounded set of blocking workers takes the newest pending range
from that window. Each range has a result channel; the service consumes those
channels in ascending source order using the existing authentication, atomic
artifact persistence and event-loop handoff. Completed newer results wait in the
same bounded window. Only a fully drained window permits another reservation.
This bounds retained entries/results and prevents live arrivals from starving the
reserved frontier. Sequential mode retains its existing sliding window.

Graceful shutdown stops new admission, drains all reserved work and joins the CPU
workers. An exited worker closes its current result channel; failure follows the
existing failed-proof reservation cleanup. Dropping the service handle still
cannot forcibly cancel CPU work, as documented by the existing service contract.
No transaction format, proof format, activation schedule or settlement rule changes.

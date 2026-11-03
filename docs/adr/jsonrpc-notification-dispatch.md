# Dispatch method notifications through the existing RPC service

The published JSON-RPC reference follows JSON-RPC 2.0. A notification invokes a
method without receiving a Response. The pinned jsonrpsee-server 0.24.11 transport
parser acknowledges single and batched notifications before invoking RPC service
middleware. A valid signed transaction submitted without an id is consequently
ignored, while its identical identified request executes.

Maintain a bounded patch of that pinned server crate in `deps/jsonrpsee-server`.
Its shared HTTP/WebSocket parser converts valid notifications into internal
requests marked in server-side extensions. The existing namespace, rate limit,
parameter, signature and permission checks execute normally; the parser discards
the returned MethodResponse. Malformed identified envelopes cannot enter this
path. An explicit null id retains ordinary identified-request behavior.

PubSub setup is an extension that requires an identified acceptance handshake.
Its callback sends the acceptance response directly to the WebSocket sink, so
an id-less setup is rejected internally before allocating a subscription.
Notification unsubscription executes normally. Unknown methods and rejected
notifications have no response and no successful state effect.

`deps/jsonrpsee-server/PATCHES.md` records archive provenance, source deviations
and the removal condition. No dependency versions are upgraded. The Rust
integration test exercises the transport dispatcher; the portable node acceptance
script verifies actual signed execution, response suppression, both WebSocket
listener modes, rejection boundaries and canonical state after restart. Review a
future upstream replacement against those behavioral checks before removing the
patch.

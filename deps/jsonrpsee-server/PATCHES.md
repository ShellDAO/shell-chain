# jsonrpsee-server notification dispatch patch

Based on the unmodified crates.io `jsonrpsee-server` 0.24.11 archive
(SHA-256 `c625c78b8d545478370b6e7a2a191b0d921f831a9eef38dc1e7efb57e7a5472f`). Source files retain their upstream license headers.

The upstream HTTP and WebSocket dispatcher acknowledges notifications without
invoking the method. This patch sends single and batched notifications through
the existing RPC middleware and callbacks, discarding their responses. It also
prevents malformed identified requests from becoming notifications and reports
valid JSON with an invalid request envelope as InvalidRequest.

PubSub setup requires an identified handshake because subscription acceptance
writes its response directly to the socket. An id-less subscription setup is
rejected internally without a response or subscription allocation; notification
unsubscription still invokes the normal callback. This does not affect ordinary
JSON-RPC method notifications or identified calls with a null ID.

Only `src/server.rs` and `src/middleware/rpc/layer/rpc_service.rs` differ from
upstream source. The normalized registry manifest omits upstream dev dependencies
and this copy is excluded from the outer workspace; integration regression tests
run in `shell-rpc`. No transitive dependency versions are upgraded. Upstream test
sources are retained for comparison. Remove the patch when the pinned upstream
version provides equivalent dispatch and response-suppression guarantees.

Run `cargo test -p shell-rpc --test notifications` and the node's portable
`python3 tests/e2e/rpc-notifications.py` acceptance entry after building it.

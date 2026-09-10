//! Shared HTTP transport for CLI JSON-RPC commands.

// Match the node's default maximum JSON-RPC response size.
const MAX_RPC_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

pub(super) fn rpc_post(
    url: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .build();
    let resp = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())?;
    use std::io::Read;

    let mut bytes = Vec::new();
    resp.into_reader()
        .take((MAX_RPC_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RPC_RESPONSE_BYTES {
        return Err(format!("RPC response exceeds {MAX_RPC_RESPONSE_BYTES} bytes").into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

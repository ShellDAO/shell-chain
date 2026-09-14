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
    let response: serde_json::Value = serde_json::from_slice(&bytes)?;
    if response.get("jsonrpc").and_then(serde_json::Value::as_str) != Some("2.0")
        || response.get("id") != body.get("id")
    {
        return Err("RPC response does not match request version or ID".into());
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    fn request_with_response(response: serde_json::Value) -> Result<serde_json::Value, String> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(&mut socket);
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse::<usize>().unwrap();
                    }
                }
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            let response = response.to_string();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
        });
        let result = rpc_post(
            &url,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []
            }),
        )
        .map_err(|error| error.to_string());
        server.join().unwrap();
        result
    }

    #[test]
    fn rpc_rejects_mismatched_response_identity() {
        for response in [
            serde_json::json!({"jsonrpc": "2.0", "id": 2, "result": "0x1"}),
            serde_json::json!({"jsonrpc": "2.0", "id": "1", "result": "0x1"}),
            serde_json::json!({"jsonrpc": "2.0", "result": "0x1"}),
            serde_json::json!({"jsonrpc": "1.0", "id": 1, "result": "0x1"}),
            serde_json::json!({"id": 1, "result": "0x1"}),
            serde_json::json!({"jsonrpc": "2.0", "id": 2, "error": {"code": -32000, "message": "rejected"}}),
        ] {
            assert!(
                request_with_response(response.clone()).is_err(),
                "accepted {response}"
            );
        }
    }

    #[test]
    fn rpc_preserves_matching_success_and_error_responses() {
        for response in [
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": "0x1"}),
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "rejected"}}),
        ] {
            assert_eq!(request_with_response(response.clone()).unwrap(), response);
        }
    }
}

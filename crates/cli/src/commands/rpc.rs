//! Shared HTTP transport for CLI JSON-RPC commands.

// Match the node's default maximum JSON-RPC response size.
const MAX_RPC_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
const MAX_RPC_API_KEY_BYTES: usize = 4096;
const RPC_API_KEY_FILE_ENV: &str = "SHELL_RPC_API_KEY_FILE";

pub(super) fn rpc_post(
    url: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let key_file = std::env::var_os(RPC_API_KEY_FILE_ENV);
    rpc_post_with_key_file(url, body, key_file.as_deref().map(std::path::Path::new))
}

fn read_rpc_api_key(path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    let contents = crate::secure_file::read_sensitive_file(path)
        .map_err(|_| "cannot read SHELL_RPC_API_KEY_FILE as a regular UTF-8 file")?;
    // Permit a text file's single final line ending, not embedded whitespace.
    let token = contents
        .strip_suffix("\r\n")
        .or_else(|| contents.strip_suffix('\n'))
        .unwrap_or(&contents);
    if token.is_empty()
        || token.len() > MAX_RPC_API_KEY_BYTES
        || !token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(
            "SHELL_RPC_API_KEY_FILE must contain one nonempty ASCII token of at most 4096 bytes"
                .into(),
        );
    }
    Ok(token.to_owned())
}

fn rpc_post_with_key_file(
    url: &str,
    body: &serde_json::Value,
    key_file: Option<&std::path::Path>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let api_key = key_file.map(read_rpc_api_key).transpose()?;
    let mut builder = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(5));
    if api_key.is_some() {
        // Require the operator's exact endpoint; never forward its credential.
        builder = builder.redirects(0);
    }
    let agent = builder.build();
    let mut request = agent.post(url).set("Content-Type", "application/json");
    if let Some(key) = &api_key {
        request = request.set("Authorization", &format!("Bearer {key}"));
    }
    let resp = request.send_string(&body.to_string()).map_err(|error| {
        if api_key.is_none() {
            return Box::<dyn std::error::Error>::from(error);
        }
        // Transport errors may quote URLs or header values. Keep credentials
        // out of diagnostics, including a peer-supplied HTTP status message.
        match error {
            ureq::Error::Status(code, _) => {
                format!("authenticated RPC request failed with HTTP {code}").into()
            }
            ureq::Error::Transport(_) => "authenticated RPC transport failed".into(),
        }
    })?;
    if api_key.is_some() && (300..400).contains(&resp.status()) {
        return Err("authenticated RPC redirects are not allowed; use the final RPC URL".into());
    }
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
        let result = rpc_post_with_key_file(
            &url,
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []
            }),
            None,
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

    #[test]
    fn rpc_api_key_file_rejects_unsafe_contents_before_connecting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-key");
        for contents in [
            Vec::new(),
            b"\n".to_vec(),
            b"secret\r\nInjected: header".to_vec(),
            b"secret\0".to_vec(),
            b"secret other".to_vec(),
            b"secret\n\n".to_vec(),
            vec![b'x'; MAX_RPC_API_KEY_BYTES + 1],
            vec![0xff],
        ] {
            std::fs::write(&path, contents).unwrap();
            let error = rpc_post_with_key_file(
                "http://127.0.0.1:0",
                &serde_json::json!({"jsonrpc":"2.0", "id":1}),
                Some(&path),
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains(RPC_API_KEY_FILE_ENV), "{error}");
            assert!(!error.contains("secret"), "{error}");
        }
        for contents in ["token", "token\n", "token\r\n"] {
            std::fs::write(&path, contents).unwrap();
            assert_eq!(read_rpc_api_key(&path).unwrap(), "token");
        }
        std::fs::write(&path, "x".repeat(MAX_RPC_API_KEY_BYTES)).unwrap();
        assert_eq!(
            read_rpc_api_key(&path).unwrap().len(),
            MAX_RPC_API_KEY_BYTES
        );
        assert!(read_rpc_api_key(dir.path()).is_err());
        assert!(read_rpc_api_key(&dir.path().join("missing")).is_err());
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read_rpc_api_key(&link).is_err());
        }
    }

    #[test]
    fn authenticated_rpc_sends_bearer_and_refuses_redirects_without_leaking_key() {
        let secret = "private-test-credential";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api-key");
        std::fs::write(&path, format!("{secret}\n")).unwrap();
        for status in [200, 401, 301, 302, 303, 307, 308] {
            let target = TcpListener::bind("127.0.0.1:0").unwrap();
            target.set_nonblocking(true).unwrap();
            let target_url = format!("http://{}", target.local_addr().unwrap());
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(&mut socket);
                let mut authorization = None;
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("authorization") {
                            authorization = Some(value.trim().to_owned());
                        }
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse::<usize>().unwrap();
                        }
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                assert_eq!(
                    authorization.as_deref(),
                    Some("Bearer private-test-credential")
                );
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["id"],
                    1
                );
                let body = r#"{"jsonrpc":"2.0","id":1,"result":"0x539"}"#;
                write!(socket, "HTTP/1.1 {status} {secret}\r\nLocation: {target_url}/{secret}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            });
            let result = rpc_post_with_key_file(
                &url,
                &serde_json::json!({"jsonrpc":"2.0", "id":1, "method":"eth_chainId", "params":[]}),
                Some(&path),
            );
            server.join().unwrap();
            if status == 200 {
                assert_eq!(result.unwrap()["result"], "0x539");
            } else {
                let error = result.unwrap_err().to_string();
                assert!(!error.contains(secret), "{error}");
                if status == 401 {
                    assert!(error.contains("401"));
                } else {
                    assert!(error.contains("redirects"), "{error}");
                }
            }
            assert_eq!(
                target.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
        let error = rpc_post_with_key_file(
            "invalid URL containing private-test-credential",
            &serde_json::json!({"jsonrpc":"2.0", "id":1}),
            Some(&path),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(error, "authenticated RPC transport failed");
    }
}

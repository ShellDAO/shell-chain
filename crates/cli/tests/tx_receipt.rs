use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const HASH: &str = "0xabababababababababababababababababababababababababababababababab";

fn query(mut response: Value) -> Output {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    response["jsonrpc"] = json!("2.0");
    response["id"] = json!(1);
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "CLI never requested a receipt");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(&mut socket);
        let mut length = 0;
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt", "params": [HASH]
            })
        );
        let response = response.to_string();
        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_shell-node"))
        .args([
            "tx",
            "receipt",
            &HASH.replace("ab", "AB"),
            "--rpc-url",
            &url,
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    output
}

#[test]
fn receipt_preserves_execution_status_and_unavailable_result() {
    for result in [
        Value::Null,
        json!({"transactionHash": HASH, "status": "0x1", "blockNumber": "0x12", "logs": []}),
        json!({"transactionHash": HASH, "status": "0x0", "blockNumber": "0x12", "logs": []}),
    ] {
        let output = query(json!({"result": result}));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            result
        );
    }
}

#[test]
fn receipt_rejects_rpc_errors_and_invalid_results() {
    for response in [
        json!({"error": {"code": -32000, "message": "receipt unavailable"}}),
        json!({}),
        json!({"result": []}),
        json!({"result": {}}),
        json!({"result": {"transactionHash": format!("0x{}", "00".repeat(32))}}),
    ] {
        let output = query(response);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn receipt_rejects_invalid_hash_before_network_access() {
    for hash in [
        "",
        "0x",
        "0x12",
        &"ab".repeat(32),
        &format!("0x{}", "gg".repeat(32)),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_shell-node"))
            .args(["tx", "receipt", hash, "--rpc-url", "not-a-url"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("transaction hash must"));
        assert!(output.stdout.is_empty());
    }
}

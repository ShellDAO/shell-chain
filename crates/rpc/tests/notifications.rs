use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use jsonrpsee::{
    core::client::ClientT,
    rpc_params,
    server::{BatchRequestConfig, Server},
    types::ErrorObjectOwned,
    ws_client::WsClientBuilder,
    RpcModule,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn post(addr: std::net::SocketAddr, body: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    response.split_once("\r\n\r\n").unwrap().1.to_owned()
}

#[tokio::test]
async fn notifications_execute_once_without_responses_over_http_and_ws() {
    let state = Arc::new(AtomicUsize::new(0));
    let mut module = RpcModule::new(state.clone());
    module
        .register_method("add_sync", |params, state, _| {
            let (amount,): (usize,) = params.parse()?;
            Ok::<_, ErrorObjectOwned>(state.fetch_add(amount, Ordering::SeqCst) + amount)
        })
        .unwrap();
    module
        .register_method("read", |_, state, _| state.load(Ordering::SeqCst))
        .unwrap();
    module
        .register_async_method("add", |params, state, _| async move {
            let (amount,): (usize,) = params.parse()?;
            if amount > 10 {
                return Err(ErrorObjectOwned::owned(-32000, "too large", None::<()>));
            }
            Ok(state.fetch_add(amount, Ordering::SeqCst) + amount)
        })
        .unwrap();
    let server = Server::builder()
        .set_batch_request_config(BatchRequestConfig::Limit(100))
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.start(module);

    assert_eq!(
        post(
            addr,
            r#"{"jsonrpc":"2.0","method":"add_sync","params":[3]}"#
        )
        .await,
        ""
    );
    assert_eq!(state.load(Ordering::SeqCst), 3);
    let mixed = post(addr, r#"[{"jsonrpc":"2.0","method":"add","params":[2]},{"jsonrpc":"2.0","method":"read","id":9}]"#).await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&mixed).unwrap(),
        serde_json::json!([{"jsonrpc":"2.0","id":9,"result":5}])
    );
    assert_eq!(post(addr, r#"[{"jsonrpc":"2.0","method":"add","params":[1]},{"jsonrpc":"2.0","method":"add","params":[1]}]"#).await, "");
    assert_eq!(state.load(Ordering::SeqCst), 7);
    for body in [
        r#"{"jsonrpc":"2.0","method":"add","params":[99]}"#,
        r#"{"jsonrpc":"2.0","method":"add","params":[]}"#,
        r#"{"jsonrpc":"2.0","method":"unknown"}"#,
    ] {
        assert_eq!(post(addr, body).await, "");
    }
    assert_eq!(state.load(Ordering::SeqCst), 7);
    for id in ["{}", "[]", "true"] {
        let body = format!(r#"{{"jsonrpc":"2.0","method":"add","params":[1],"id":{id}}}"#);
        let response: serde_json::Value = serde_json::from_str(&post(addr, &body).await).unwrap();
        assert_eq!(response["error"]["code"], -32600);
    }
    assert_eq!(state.load(Ordering::SeqCst), 7);
    for (body, code) in [
        (r#"{"jsonrpc":"1.0","method":"add","params":[1]}"#, -32600),
        ("{broken", -32700),
    ] {
        let response: serde_json::Value = serde_json::from_str(&post(addr, body).await).unwrap();
        assert_eq!(response["error"]["code"], code);
    }
    assert_eq!(state.load(Ordering::SeqCst), 7);
    let null: serde_json::Value = serde_json::from_str(
        &post(
            addr,
            r#"{"jsonrpc":"2.0","method":"add","params":[1],"id":null}"#,
        )
        .await,
    )
    .unwrap();
    assert!(null["id"].is_null());
    assert_eq!(null["result"], 8);
    let oversized = format!(
        "[{}]",
        vec![r#"{"jsonrpc":"2.0","method":"add","params":[1]}"#; 101].join(",")
    );
    let rejected: serde_json::Value = serde_json::from_str(&post(addr, &oversized).await).unwrap();
    assert!(rejected.get("error").is_some());
    assert_eq!(state.load(Ordering::SeqCst), 8);

    let client = WsClientBuilder::default()
        .build(format!("ws://{addr}"))
        .await
        .unwrap();
    client.notification("add", rpc_params![2]).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let n: usize = client.request("read", rpc_params![]).await.unwrap();
            if n == 10 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    handle.stop().unwrap();
    handle.stopped().await;
}

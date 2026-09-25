use super::*;

#[jsonrpsee::core::async_trait]
impl<S: KvStore + 'static> TraceApiServer for RpcHandler<S> {
    async fn trace_block(
        &self,
        block_number: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let block = self.resolve_block(&block_number)?;
        self.oe_traces(block, None).await
    }

    async fn trace_oe_transaction(
        &self,
        tx_hash: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let (block, _, _, tx_index) = self.lookup_tx_with_block(&tx_hash)?;
        self.oe_traces(block, Some(tx_index as usize)).await
    }
}

impl<S: KvStore + 'static> RpcHandler<S> {
    async fn oe_traces(
        &self,
        block: Block,
        target: Option<usize>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let options = TraceOptions {
            disable_stack: Some(true),
            disable_memory: Some(true),
            disable_storage: Some(true),
            ..TraceOptions::default()
        };
        Ok(serde_json::Value::Array(
            self.replay_traces(
                block,
                target,
                options,
                super::net::TraceFormat::OpenEthereum,
            )
            .await?,
        ))
    }
}

/// Flatten observed frames in execution order, retaining each frame's location.
pub(super) fn flatten_oe_trace(
    root: shell_pqvm::CallFrame,
    block_number: u64,
    block_hash: ShellHash,
    transaction_hash: ShellHash,
    transaction_position: u64,
) -> Result<Vec<serde_json::Value>, ErrorObjectOwned> {
    let mut pending = vec![(root, Vec::new())];
    let mut traces = Vec::new();
    let mut response_bytes = 0usize;
    while let Some((frame, trace_address)) = pending.pop() {
        let create = matches!(frame.call_type.as_str(), "CREATE" | "CREATE2");
        let value = hex_u256(frame.value.unwrap_or_default());
        let action = if create {
            OeTraceAction::Create {
                from: frame.from,
                gas: hex_u64(frame.gas),
                value,
                init: hex_bytes(frame.input.as_ref()),
            }
        } else {
            OeTraceAction::Call {
                call_type: frame.call_type.to_ascii_lowercase(),
                from: frame.from,
                to: frame.to,
                gas: hex_u64(frame.gas),
                value,
                input: hex_bytes(frame.input.as_ref()),
            }
        };
        let result = frame.error.is_none().then(|| {
            let output = hex_bytes(frame.output.as_ref().map_or(&[], |output| output.as_ref()));
            if create {
                OeTraceOutput::Create {
                    gas_used: hex_u64(frame.gas_used),
                    code: output,
                    address: frame.to,
                }
            } else {
                OeTraceOutput::Call {
                    gas_used: hex_u64(frame.gas_used),
                    output,
                }
            }
        });
        let trace = OeTrace {
            action,
            result,
            error: frame.error,
            subtraces: frame.calls.len() as u64,
            trace_address: trace_address.clone(),
            trace_type: if create { "create" } else { "call" }.into(),
            block_number,
            block_hash,
            transaction_hash,
            transaction_position,
        };
        let value = serde_json::to_value(trace).map_err(internal_err)?;
        response_bytes =
            response_bytes.saturating_add(serde_json::to_vec(&value).map_err(internal_err)?.len());
        if response_bytes > super::net::MAX_TRACE_RESPONSE_BYTES {
            return Err(server_error("trace response exceeds 16 MiB limit"));
        }
        traces.push(value);
        for (index, child) in frame.calls.into_iter().enumerate().rev() {
            let mut address = trace_address.clone();
            address.push(index as u64);
            pending.push((child, address));
        }
    }
    Ok(traces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell_pqvm::CallFrame;

    #[test]
    fn oe_frames_preserve_creation_errors_and_nested_paths() {
        let from = Address::from([0x44; 32]);
        let to = Address::from([0x55; 32]);
        let mut root = CallFrame::new("BATCH", from, to, 100_000, Bytes::default());
        let mut call = CallFrame::new("DELEGATECALL", to, from, 20_000, Bytes::from(vec![1, 2]));
        let mut create = CallFrame::new("CREATE2", from, to, 10_000, Bytes::from(vec![0x60, 0x00]));
        create.output = Some(Bytes::from(vec![0x00]));
        call.calls.push(create);
        let mut failed = CallFrame::new("CREATE", from, Address::ZERO, 10_000, Bytes::default());
        failed.error = Some("execution reverted".into());
        failed.output = Some(Bytes::from(vec![0xff]));
        root.calls = vec![call, failed];
        let traces = flatten_oe_trace(root, 7, ShellHash::ZERO, ShellHash::ZERO, 2).unwrap();
        assert_eq!(traces.len(), 4);
        assert_eq!(traces[0]["action"]["callType"], "batch");
        assert_eq!(traces[0]["subtraces"], 2);
        assert_eq!(traces[1]["action"]["callType"], "delegatecall");
        assert_eq!(traces[1]["traceAddress"], serde_json::json!([0]));
        assert_eq!(
            traces[1]["action"]["from"],
            serde_json::to_value(to).unwrap()
        );
        assert_eq!(traces[2]["traceAddress"], serde_json::json!([0, 0]));
        assert_eq!(traces[2]["type"], "create");
        assert_eq!(traces[2]["action"]["init"], "0x6000");
        assert!(traces[2]["action"].get("input").is_none());
        assert!(traces[2]["action"].get("to").is_none());
        assert_eq!(
            traces[2]["result"]["address"],
            serde_json::to_value(to).unwrap()
        );
        assert_eq!(traces[2]["result"]["code"], "0x00");
        assert_eq!(traces[3]["traceAddress"], serde_json::json!([1]));
        assert_eq!(traces[3]["error"], "execution reverted");
        assert!(traces[3].get("result").is_none());
    }
}

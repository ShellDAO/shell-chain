//! Controlled persistent refusal of the complete third-source owner index batch.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};

const PREFIX: &[u8] = b"local/quorum-production/v1/";
const FAILURE: &str = "injected quorum job index batch failure";

fn rows_digest(rows: &Rows) -> ShellHash {
    rows.iter().fold(ShellHash::ZERO, |prior, (key, value)| {
        blake3_hash(
            &[
                prior.as_bytes().as_slice(),
                &(key.len() as u64).to_be_bytes(),
                key.as_slice(),
                blake3_hash(value).as_bytes(),
            ]
            .concat(),
        )
    })
}
fn save(path: &Path, value: &Value) -> Result<(), Error> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    serde_json::to_writer_pretty(file, value)?;
    Ok(())
}
fn baseline<S: KvStore + 'static>(n: &Node<S>, c: &Control) -> Result<Value, Error> {
    ensure(
        n.chain_store.get_head_hash()? == Some(c.blocks[2].hash())
            && n.chain_store.get_finalized_number()? == Some(3)
            && n.quorum_production_status(c.blocks[2].hash())?.is_none(),
        "fault prefix requires Native3 with no third owner source",
    )?;
    let index: Value = serde_json::from_slice(
        &n.store
            .get(&[PREFIX, b"jobs"].concat())?
            .ok_or("two-job owner index absent")?,
    )?;
    ensure(
        index == serde_json::to_value(vec![c.blocks[0].hash(), c.blocks[1].hash()])?,
        "fault prefix must retain the original two-job index",
    )?;
    let cache = shell_storage::CanonicalProofUploadStore::new(n.store.clone());
    let mut counts = Vec::new();
    for block in &c.blocks[..2] {
        let status = n
            .quorum_production_status(block.hash())?
            .ok_or("completed owner source absent")?;
        let manifest = completed(&status)?;
        ensure(
            cache.available_manifests()?.contains(&manifest)
                && !cache.payload(&manifest.id())?.is_empty(),
            "completed owner availability absent",
        )?;
        counts.push(status["status"]["components"].clone());
    }
    Ok(
        json!({"logicalRowsDigest":rows_digest(&n.store.scan_all()?),"Native3":recovery_native_digest(n)?,"ownerIndex":index,"components":counts,"thirdAbsent":true}),
    )
}
struct IndexBatchFailure {
    inner: RocksDbStore,
    third: ShellHash,
    index: Value,
    attempts: AtomicUsize,
    complete_tuple: AtomicBool,
}
impl KvStore for IndexBatchFailure {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, shell_storage::StorageError> {
        self.inner.get(key)
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), shell_storage::StorageError> {
        self.inner.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> Result<(), shell_storage::StorageError> {
        self.inner.delete(key)
    }
    fn flush(&self) -> Result<(), shell_storage::StorageError> {
        self.inner.flush()
    }
    fn scan_prefix(&self, prefix: &[u8]) -> Result<Rows, shell_storage::StorageError> {
        self.inner.scan_prefix(prefix)
    }
    fn snapshot_prefixes(
        &self,
        prefixes: &[&[u8]],
        max_bytes: usize,
    ) -> Result<std::collections::BTreeMap<Vec<u8>, Vec<u8>>, shell_storage::StorageError> {
        self.inner.snapshot_prefixes(prefixes, max_bytes)
    }
    fn write_batch(
        &self,
        batch: shell_storage::WriteBatch,
    ) -> Result<(), shell_storage::StorageError> {
        let puts = batch
            .ops()
            .iter()
            .filter_map(|op| match op {
                shell_storage::WriteBatchOp::Put { key, value } => Some((key, value)),
                _ => None,
            })
            .collect::<Vec<_>>();
        let source_key = [PREFIX, b"source/", self.third.as_bytes()].concat();
        if puts.iter().any(|(key, _)| **key == source_key) {
            let index_key = [PREFIX, b"jobs"].concat();
            let record_key = [PREFIX, b"record/", self.third.as_bytes()].concat();
            let bytes_key = [PREFIX, b"bytes"].concat();
            let complete = puts.len() == 4
                && batch.ops().len() == 4
                && puts.iter().any(|(key, value)| {
                    **key == index_key
                        && serde_json::from_slice::<Value>(value)
                            .is_ok_and(|index| index == self.index)
                })
                && puts.iter().any(|(key, _)| **key == record_key)
                && puts
                    .iter()
                    .any(|(key, value)| **key == bytes_key && value.len() == 8);
            self.attempts.fetch_add(1, SeqCst);
            self.complete_tuple.store(complete, SeqCst);
            return Err(shell_storage::StorageError::Database(FAILURE.into()));
        }
        self.inner.write_batch(batch)
    }
}
pub(super) async fn exercise(args: &[String]) -> Result<(), Error> {
    let c = successor::controls(Path::new(&args[1]))?;
    let root = Path::new(&args[5]);
    let checkpoint = root.join("producer-history-baseline.json");
    if args[0] == "producer-history-prepare" {
        prepare_prefix(&c, Path::new(&args[1]), &args[2..5], root).await?;
        let n = node(&root.join("provider-db"), &c, false)?;
        let saved = baseline(&n, &c)?;
        save(&checkpoint, &saved)?;
        println!(
            "{}",
            json!({"historyFaultPrefixPrepared":true,"baseline":saved,"newProofMath":0})
        );
        return Ok(());
    }
    let cold = args[0] == "producer-history-fault-cold";
    ensure(
        cold || args[0] == "producer-history-fault",
        "unknown owner fault mode",
    )?;
    let previous = std::fs::read_dir(root)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .filter(|name| name.starts_with("producer-history-refusal-") && name.ends_with(".json"))
        .count();
    ensure(
        (previous > 0) == cold && previous < 16,
        "fault process sequence mismatch",
    )?;
    let saved: Value = serde_json::from_slice(&std::fs::read(checkpoint)?)?;
    let store = Arc::new(IndexBatchFailure {
        inner: RocksDbStore::open_all(root.join("provider-db"), None)?.state,
        third: c.blocks[2].hash(),
        index: json!({"version":2,"active":[c.blocks[1].hash(),c.blocks[2].hash()],"completed":[c.blocks[0].hash()]}),
        attempts: AtomicUsize::new(0),
        complete_tuple: AtomicBool::new(false),
    });
    let initial = node_on_store(store.clone(), &c, false)?;
    ensure(
        baseline(&initial, &c)? == saved,
        "fault prefix differs from preserved baseline",
    )?;
    let before = store.scan_all()?;
    let error = match Live::start_on_node(initial, &c, vec![], false, true).await {
        Err(error) => error.to_string(),
        Ok(live) => {
            // RPC may bind before the producer's startup capture has finished.
            tokio::time::timeout(Duration::from_secs(20), async {
                while !live.task.is_finished() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await?;
            match live.stop().await {
                Err(error) => error.to_string(),
                Ok(()) => "node unexpectedly exited without the source-index refusal".into(),
            }
        }
    };
    let rows_unchanged = store.scan_all()? == before;
    let released = tokio::time::timeout(Duration::from_secs(5), async {
        while Arc::strong_count(&store) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok();
    store.flush()?;
    let observed = json!({"processAttempt":previous+1,"coldProcess":cold,"error":error,"completeSourceIndexCounterBatch":store.complete_tuple.load(SeqCst),"databaseRefusals":store.attempts.load(SeqCst),"allLogicalRowsUnchanged":rows_unchanged,"baselineDigest":rows_digest(&before),"backendReleasedAfterStartupFailure":released,"backendStrongCount":Arc::strong_count(&store),"newProofMath":0});
    save(
        &root.join(format!("producer-history-refusal-{}.json", previous + 1)),
        &observed,
    )?;
    println!("{observed}");
    ensure(
        error.contains(FAILURE)
            && store.attempts.load(SeqCst) == 1
            && store.complete_tuple.load(SeqCst)
            && rows_unchanged,
        "owner batch refusal changed retained state or was not observed",
    )?;
    ensure(released, "startup failure retained RPC/backend resources")
}

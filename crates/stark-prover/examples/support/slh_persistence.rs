//! Shared bounded immutable I/O and concrete XMSS checkpoint persistence.
use shell_stark_prover::{
    sha2_compression::{
        prove_compression_batch, verify_compression_batch, Sha2Algorithm, Sha2CompressionProof,
    },
    slh_sha2::{prove_slh_sha2, verify_slh_sha2, SlhSha2Proof},
    slh_xmss::{prove_xmss_using, verify_xmss, SlhXmssInputs, SlhXmssProof},
};
use std::{error::Error, path::Path};
#[path = "certificate_io.rs"]
mod io;
pub use io::{decode, encode, read, write};
pub fn persist_xmss(
    input: &SlhXmssInputs,
    dir: &Path,
    resume: bool,
    shared_prefix: Option<&Sha2CompressionProof>,
) -> Result<(SlhXmssProof, usize, usize), Box<dyn Error>> {
    let final_path = dir.join("xmss.cbor");
    if !resume && final_path.exists() {
        return Err("original XMSS proof exists; use resume to recheck".into());
    }
    std::fs::create_dir_all(dir)?;
    let frozen = dir.join("inputs.json");
    let bytes = serde_json::to_vec(input)?;
    if frozen.exists() {
        if read(&frozen, 32_768)? != bytes {
            return Err("retained XMSS inputs differ; refusing replacement".into());
        }
    } else {
        if std::fs::read_dir(dir)?.next().is_some() {
            return Err("unowned nonempty XMSS output directory".into());
        }
        write(&frozen, &bytes)?;
    }
    // Separate counters avoid sharing mutable state between the providers.
    let mut c_new = 0usize;
    let mut c_old = 0usize;
    let mut h_new = 0usize;
    let mut h_old = 0usize;
    let proof = prove_xmss_using(
        input,
        |at, inputs| {
            let path = dir.join(format!("compression-{at:03}.cbor"));
            if path.exists() {
                c_old += 1;
                return decode::<Sha2CompressionProof>(
                    &read(&path, 8 * 1024 * 1024).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string());
            }
            let proof = if let Some(prefix) = shared_prefix.filter(|_| at == 0) {
                c_old += 1;
                prefix.clone()
            } else {
                c_new += 1;
                prove_compression_batch(Sha2Algorithm::Sha256, inputs)?
            };
            verify_compression_batch(&proof, Sha2Algorithm::Sha256, inputs)?;
            write(&path, &encode(&proof).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            Ok(proof)
        },
        |at, request| {
            let path = dir.join(format!("hash-{at:03}.cbor"));
            if path.exists() {
                h_old += 1;
                return decode::<SlhSha2Proof>(
                    &read(&path, 16 * 1024 * 1024).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string());
            }
            let proof = prove_slh_sha2(request)?;
            verify_slh_sha2(&proof, request)?;
            write(&path, &encode(&proof).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            h_new += 1;
            Ok(proof)
        },
    )?;

    verify_xmss(&proof, input)?;
    let bytes = encode(&proof)?;
    if final_path.exists() {
        if read(&final_path, 64 * 1024 * 1024)? != bytes {
            return Err("retained XMSS certificate differs; refusing replacement".into());
        }
    } else {
        write(&final_path, &bytes)?;
    }
    Ok((proof, c_new + h_new, c_old + h_old))
}

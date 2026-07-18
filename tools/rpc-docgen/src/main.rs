//! rpc-docgen: Generate docs/rpc-reference.md from crates/rpc/src/api.rs
//!
//! Usage:
//!   rpc-docgen               — regenerate docs/rpc-reference.md (in-place)
//!   rpc-docgen --check       — exit 1 if the generated output differs from
//!                              the committed docs/rpc-reference.md
//!
//! The tool parses the jsonrpsee `#[rpc(server, namespace = "...")]` and
//! `#[method(name = "...")]` attributes plus the preceding `///` doc comments
//! from `crates/rpc/src/api.rs` to produce a stable markdown reference.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

// ── Types ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Namespace {
    name: String,
    methods: Vec<RpcMethod>,
}

#[derive(Debug)]
struct RpcMethod {
    /// Full RPC name, e.g. `eth_blockNumber`
    rpc_name: String,
    /// Rust function signature (params + return stripped of wrappers)
    signature: String,
    /// Collected `///` doc comment lines
    doc: Vec<String>,
}

// ── Parser ─────────────────────────────────────────────────────────────────

fn parse_api(src: &str) -> Vec<Namespace> {
    let mut namespaces: Vec<Namespace> = Vec::new();
    let mut current_ns: Option<String> = None;
    let mut pending_docs: Vec<String> = Vec::new();
    let mut pending_method_name: Option<String> = None;
    let mut in_fn_sig: bool = false;
    let mut fn_sig_lines: Vec<String> = Vec::new();

    for line in src.lines() {
        let trimmed = line.trim();

        // ── Namespace declaration: #[rpc(server, namespace = "foo")]
        if trimmed.starts_with("#[rpc(") {
            if let Some(ns) = extract_attr_value(trimmed, "namespace") {
                current_ns = Some(ns.clone());
                namespaces.push(Namespace {
                    name: ns,
                    methods: Vec::new(),
                });
                pending_docs.clear();
                pending_method_name = None;
            }
            continue;
        }

        // ── Doc comment
        if let Some(doc_line) = trimmed.strip_prefix("/// ") {
            pending_docs.push(doc_line.to_string());
            continue;
        }
        if trimmed == "///" {
            pending_docs.push(String::new());
            continue;
        }
        // Non-doc comment or code — if not continuing a fn sig, reset docs
        // only when we're not in the middle of collecting something.

        // ── Method attribute: #[method(name = "foo")]
        if trimmed.starts_with("#[method(name") {
            if let Some(method_name) = extract_attr_value(trimmed, "name") {
                pending_method_name = Some(method_name);
            }
            continue;
        }

        // ── Function signature start
        if (trimmed.starts_with("async fn ") || trimmed.starts_with("fn "))
            && pending_method_name.is_some()
        {
            in_fn_sig = true;
            fn_sig_lines.clear();
            fn_sig_lines.push(trimmed.to_string());

            // Might be complete on one line
            if trimmed.ends_with(';') || trimmed.contains(") -> ") && trimmed.ends_with(';') {
                in_fn_sig = false;
                flush_method(
                    &mut namespaces,
                    &current_ns,
                    &mut pending_docs,
                    &mut pending_method_name,
                    &fn_sig_lines,
                );
            }
            continue;
        }

        // ── Continuing a multi-line function signature
        if in_fn_sig {
            fn_sig_lines.push(trimmed.to_string());
            if trimmed.ends_with(';') {
                in_fn_sig = false;
                flush_method(
                    &mut namespaces,
                    &current_ns,
                    &mut pending_docs,
                    &mut pending_method_name,
                    &fn_sig_lines,
                );
            }
            continue;
        }

        // ── Reset pending docs on blank lines or non-doc content before a method
        if (trimmed.is_empty() || (!trimmed.starts_with("//") && !trimmed.starts_with('#')))
            && pending_method_name.is_none()
        {
            pending_docs.clear();
        }
    }

    namespaces
}

fn flush_method(
    namespaces: &mut [Namespace],
    current_ns: &Option<String>,
    pending_docs: &mut Vec<String>,
    pending_method_name: &mut Option<String>,
    fn_sig_lines: &[String],
) {
    let ns_name = match current_ns {
        Some(n) => n,
        None => return,
    };
    let method_name = match pending_method_name.take() {
        Some(m) => m,
        None => return,
    };

    let rpc_name = format!("{ns_name}_{method_name}");
    let signature = build_signature(fn_sig_lines);
    let doc = std::mem::take(pending_docs);

    if let Some(ns) = namespaces.iter_mut().find(|n| n.name == *ns_name) {
        ns.methods.push(RpcMethod {
            rpc_name,
            signature,
            doc,
        });
    }
}

fn extract_attr_value(attr: &str, key: &str) -> Option<String> {
    let needle = format!("{key} = \"");
    let start = attr.find(&needle)? + needle.len();
    let end = attr[start..].find('"')? + start;
    Some(attr[start..end].to_string())
}

/// Build a compact human-readable signature from raw lines.
fn build_signature(lines: &[String]) -> String {
    // Join and strip `async fn` prefix and trailing `;`
    let joined = lines.join(" ");
    let joined = joined
        .trim_start_matches("async ")
        .trim_start_matches("fn ")
        .trim_end_matches(';')
        .to_string();

    // Simplify return types: strip Result<T, ErrorObjectOwned> → T
    let joined = simplify_return_type(&joined);

    // Remove &self, prefix
    joined
        .replacen("(&self, ", "(", 1)
        .replacen("(&self)", "()", 1)
        .replacen("( &self, ", "(", 1)
        .replacen("( &self )", "()", 1)
}

fn simplify_return_type(sig: &str) -> String {
    // Replace `Result<T, jsonrpsee::types::ErrorObjectOwned>` with `→ T`
    if let Some(pos) = sig.rfind("-> Result<") {
        let prefix = &sig[..pos];
        let rest = &sig[pos + "-> Result<".len()..];
        // Find the matching closing angle bracket for Result<
        let mut depth = 1i32;
        let mut end = 0;
        for (i, ch) in rest.char_indices() {
            match ch {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let inner = &rest[..end];
        // Strip trailing `, jsonrpsee::types::ErrorObjectOwned`
        let inner = inner
            .trim_end_matches(", jsonrpsee::types::ErrorObjectOwned")
            .trim();
        return format!("{prefix}→ {inner}");
    }
    sig.to_string()
}

// ── Renderer ───────────────────────────────────────────────────────────────

fn render(namespaces: &[Namespace]) -> String {
    let mut out = String::new();

    out.push_str("# RPC Reference\n\n");
    out.push_str("> **Auto-generated** by `tools/rpc-docgen` from `crates/rpc/src/api.rs`.\n");
    out.push_str("> Run `cargo run -p rpc-docgen` to regenerate.\n\n");
    out.push_str("shell-chain exposes the following JSON-RPC namespaces:\n\n");

    for ns in namespaces {
        out.push_str(&format!(
            "- **`{}_`** ({} methods)\n",
            ns.name,
            ns.methods.len()
        ));
    }
    out.push('\n');
    out.push_str("All methods use JSON-RPC 2.0. Hex quantities are `0x`-prefixed strings.\n\n");
    out.push_str("Error codes are defined in `crates/rpc/src/error.rs`:\n\n");
    out.push_str(
        "| Code    | Constant            | Meaning                                     |\n",
    );
    out.push_str(
        "|---------|---------------------|---------------------------------------------|\n",
    );
    out.push_str(
        "| `-32601`| `METHOD_NOT_FOUND`  | Method not found or not enabled             |\n",
    );
    out.push_str(
        "| `-32602`| `INVALID_PARAMS`    | Invalid parameters                          |\n",
    );
    out.push_str(
        "| `-32603`| `INTERNAL_ERROR`    | Internal server error                       |\n",
    );
    out.push_str(
        "| `-32000`| `SERVER_ERROR`      | Generic server / precondition failure       |\n",
    );
    out.push_str(
        "| `-32001`| `NOT_FOUND`         | Resource (block, filter, tx) not found      |\n",
    );
    out.push_str(
        "| `-32002`| `DEV_MODE_REQUIRED` | Operation requires dev mode                 |\n",
    );
    out.push_str(
        "| `-32003`| `FEATURE_NOT_ENABLED`| Feature not enabled on this node           |\n",
    );
    out.push_str(
        "| `-32005`| `LIMIT_EXCEEDED`    | Result limit exceeded (eth_getLogs)         |\n",
    );
    out.push_str("\n---\n");

    for ns in namespaces {
        out.push_str(&format!("\n## {}_  namespace\n\n", ns.name));
        for method in &ns.methods {
            out.push_str(&format!("### {}\n", method.rpc_name));
            // Signature
            out.push_str(&format!("```\n{}\n```\n", method.signature));
            // Doc comment
            if !method.doc.is_empty() {
                out.push('\n');
                for line in &method.doc {
                    out.push_str(line);
                    out.push('\n');
                }
            }
            out.push('\n');
        }
    }

    out
}

// ── Main ───────────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("rpc-docgen must remain under tools/rpc-docgen")
        .to_path_buf()
}

fn write_generated(path: &Path, generated: &str) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output path has no parent"))?;
    let parent_meta = fs::symlink_metadata(parent)?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output parent must be a real directory",
        ));
    }

    let temp_path = parent.join(format!(".rpc-reference.md.tmp-{}", process::id()));
    let mut temp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    let result = (|| {
        temp.write_all(generated.as_bytes())?;
        temp.sync_all()?;
        drop(temp);
        fs::rename(&temp_path, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn main() {
    let check_mode = env::args().any(|a| a == "--check");

    let root = repo_root();
    let api_path = root.join("crates/rpc/src/api.rs");
    let out_path = root.join("docs/rpc-reference.md");

    let src = fs::read_to_string(&api_path)
        .unwrap_or_else(|e| panic!("Cannot read {}: {e}", api_path.display()));

    let namespaces = parse_api(&src);
    let generated = render(&namespaces);

    if check_mode {
        let existing = fs::read_to_string(&out_path).unwrap_or_default();
        if existing == generated {
            println!("rpc-docgen: docs/rpc-reference.md is up-to-date ✓");
        } else {
            eprintln!("rpc-docgen: docs/rpc-reference.md is STALE — run `cargo run -p rpc-docgen` to regenerate");
            show_diff(&existing, &generated);
            process::exit(1);
        }
    } else {
        write_generated(&out_path, &generated)
            .unwrap_or_else(|e| panic!("Cannot write {}: {e}", out_path.display()));
        let method_count: usize = namespaces.iter().map(|n| n.methods.len()).sum();
        println!(
            "rpc-docgen: wrote {} methods across {} namespaces → {}",
            method_count,
            namespaces.len(),
            out_path.display()
        );
    }
}

fn show_diff(old: &str, new: &str) {
    // Simple line-diff summary
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let max = old_lines.len().max(new_lines.len());
    let mut shown = 0;
    for i in 0..max {
        let ol = old_lines.get(i).copied().unwrap_or("<missing>");
        let nl = new_lines.get(i).copied().unwrap_or("<missing>");
        if ol != nl {
            eprintln!("  line {}: - {ol}", i + 1);
            eprintln!("  line {}: + {nl}", i + 1);
            shown += 1;
            if shown >= 20 {
                eprintln!("  ... (more differences, run with --verbose for full diff)");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
/// Web3 namespace.
#[rpc(server, namespace = "web3")]
pub trait Web3Api {
    /// Returns the client version.
    #[method(name = "clientVersion")]
    async fn client_version(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Returns the sha3 of the given data.
    #[method(name = "sha3")]
    async fn sha3(&self, data: String) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;
}

/// Eth namespace.
#[rpc(server, namespace = "eth")]
pub trait EthApi {
    /// Returns the block number.
    #[method(name = "blockNumber")]
    async fn block_number(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;
}
"#;

    #[test]
    fn parses_namespaces() {
        let ns = parse_api(SAMPLE);
        assert_eq!(ns.len(), 2);
        assert_eq!(ns[0].name, "web3");
        assert_eq!(ns[1].name, "eth");
    }

    #[test]
    fn parses_methods() {
        let ns = parse_api(SAMPLE);
        assert_eq!(ns[0].methods.len(), 2);
        assert_eq!(ns[0].methods[0].rpc_name, "web3_clientVersion");
        assert_eq!(ns[0].methods[1].rpc_name, "web3_sha3");
    }

    #[test]
    fn parses_doc_comments() {
        let ns = parse_api(SAMPLE);
        assert!(ns[0].methods[0].doc[0].contains("client version"));
    }

    #[test]
    fn simplifies_return_type() {
        let sig = "foo(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>";
        assert!(simplify_return_type(sig).contains("→ String"));
    }

    #[test]
    fn repo_root_is_bound_to_the_build_workspace() {
        let root = repo_root();
        assert_eq!(
            root.join("tools/rpc-docgen"),
            Path::new(env!("CARGO_MANIFEST_DIR"))
        );
        assert!(root.join("crates/rpc/src/api.rs").is_file());
        assert!(root.join("docs/rpc-reference.md").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn generated_output_replaces_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.md");
        let output = dir.path().join("rpc-reference.md");
        fs::write(&target, "original").unwrap();
        symlink(&target, &output).unwrap();

        write_generated(&output, "generated").unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
        assert_eq!(fs::read_to_string(&output).unwrap(), "generated");
        assert!(!fs::symlink_metadata(&output)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

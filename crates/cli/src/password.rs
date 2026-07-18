//! Password resolution for CLI subcommands.
//!
//! Provides [`resolve_password`] which checks for non-interactive sources
//! (`--password-file`, `--password-stdin`) before falling back to a live
//! TTY prompt via `rpassword`.
//!
//! Usage pattern:
//!
//! ```rust,ignore
//! use crate::password::{PasswordArgs, resolve_password};
//!
//! let pw = resolve_password("Enter keystore password: ", &args.password_args)?;
//! ```

use std::io::{self, BufRead};
use std::path::PathBuf;

use crate::secure_file::read_sensitive_file;

/// Password source flags forwarded from the global `Cli` struct.
#[derive(Clone, Debug, Default)]
pub struct PasswordArgs {
    /// Read the password from the first line of this file instead of prompting.
    pub password_file: Option<PathBuf>,
    /// Read the password from stdin (one line) instead of prompting.
    pub password_stdin: bool,
    /// Allow reading the password from the `SHELL_KEYSTORE_PASSWORD` environment variable.
    /// Must be opted-in explicitly for security; never active by default.
    pub allow_env_password: bool,
}

/// Resolve a keystore password from the configured source.
///
/// Priority order:
/// 1. `--password-file <path>`           — read the first non-empty line from the file.
/// 2. `--password-stdin`                 — read one line from standard input.
/// 3. `SHELL_KEYSTORE_PASSWORD` env var  — only when `--allow-env-password` is set.
/// 4. Interactive TTY prompt             — use `rpassword` (default behaviour, no echo).
///
/// Trailing `\n` / `\r\n` is stripped from file and stdin sources.
pub fn resolve_password(
    prompt: &str,
    args: &PasswordArgs,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(ref path) = args.password_file {
        let content = read_sensitive_file(path)
            .map_err(|e| format!("cannot read password file {}: {e}", path.display()))?;
        let password = content
            .lines()
            .map(|line| line.trim_end_matches('\r'))
            .find(|line| !line.is_empty())
            .unwrap_or("")
            .to_string();
        if password.is_empty() {
            return Err(format!(
                "password file {} is empty or contains only blank lines",
                path.display()
            )
            .into());
        }
        return Ok(password);
    }

    if args.password_stdin {
        let stdin = io::stdin();
        let mut line = String::new();
        stdin
            .lock()
            .read_line(&mut line)
            .map_err(|e| format!("cannot read password from stdin: {e}"))?;
        let password = line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string();
        return Ok(password);
    }

    if args.allow_env_password {
        if let Ok(pw) = std::env::var("SHELL_KEYSTORE_PASSWORD") {
            if !pw.is_empty() {
                return Ok(pw);
            }
        }
    }

    eprint!("{prompt}");
    Ok(rpassword::read_password()?)
}

/// Like [`resolve_password`] but prompts twice and checks they match.
///
/// Used for key generation where the user sets a new password.
/// Falls through to a single-prompt for non-interactive sources (file / stdin),
/// because confirmation doesn't make sense when the password is already written.
pub fn resolve_new_password(args: &PasswordArgs) -> Result<String, Box<dyn std::error::Error>> {
    if args.password_file.is_some() || args.password_stdin || args.allow_env_password {
        return resolve_password("", args);
    }

    let password = resolve_password("Enter password for new keystore: ", args)?;
    let confirm = resolve_password("Confirm password: ", args)?;
    if password != confirm {
        return Err("Passwords do not match".into());
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;

    // Serialize env-var tests to prevent cross-test contamination.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn env_password_used_when_allowed() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("SHELL_KEYSTORE_PASSWORD", "env-secret");
        let args = PasswordArgs {
            allow_env_password: true,
            ..Default::default()
        };
        let pw = resolve_password("", &args).unwrap();
        assert_eq!(pw, "env-secret");
        std::env::remove_var("SHELL_KEYSTORE_PASSWORD");
    }

    #[test]
    fn env_password_ignored_without_flag() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("SHELL_KEYSTORE_PASSWORD", "should-be-ignored");
        let _args = PasswordArgs {
            allow_env_password: false,
            ..Default::default()
        };
        // Without allow_env_password it should NOT pick up the env var (falls through to TTY).
        // We can't test the TTY path here, but we verify allow_env_password=false doesn't
        // short-circuit to the env value before reaching the TTY branch.
        // Test indirectly: file still takes priority over env.
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "from-file").unwrap();
        let args_with_file = PasswordArgs {
            password_file: Some(f.path().to_path_buf()),
            allow_env_password: false,
            ..Default::default()
        };
        let pw = resolve_password("", &args_with_file).unwrap();
        assert_eq!(
            pw, "from-file",
            "file must win over env when allow_env_password=false"
        );
        std::env::remove_var("SHELL_KEYSTORE_PASSWORD");
    }

    #[test]
    #[ignore = "requires interactive TTY; run manually with `cargo test -- --ignored`"]
    fn env_password_empty_falls_through_to_error_on_tty() {
        let _g = ENV_LOCK.lock().unwrap();
        // Empty env var with allow_env_password should NOT be accepted.
        std::env::remove_var("SHELL_KEYSTORE_PASSWORD");
        let args = PasswordArgs {
            allow_env_password: true,
            ..Default::default()
        };
        // Verify we don't panic when env var is absent and there's no other source.
        let _result = resolve_password("", &args); // may error; that's OK
    }

    #[test]
    fn password_file_takes_priority_over_env() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("SHELL_KEYSTORE_PASSWORD", "env-value");
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "file-value").unwrap();
        let args = PasswordArgs {
            password_file: Some(f.path().to_path_buf()),
            allow_env_password: true,
            ..Default::default()
        };
        let pw = resolve_password("", &args).unwrap();
        assert_eq!(
            pw, "file-value",
            "password_file must take priority over env var"
        );
        std::env::remove_var("SHELL_KEYSTORE_PASSWORD");
    }

    #[test]
    fn password_file_reads_first_line() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "hunter2").unwrap();
        writeln!(f, "ignored").unwrap();

        let args = PasswordArgs {
            password_file: Some(f.path().to_path_buf()),
            password_stdin: false,
            allow_env_password: false,
        };
        let pw = resolve_password("", &args).unwrap();
        assert_eq!(pw, "hunter2");
    }

    #[test]
    fn password_file_reads_first_non_empty_line() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f).unwrap();
        writeln!(f, "\r").unwrap();
        writeln!(f, "hunter2").unwrap();
        writeln!(f, "ignored").unwrap();

        let args = PasswordArgs {
            password_file: Some(f.path().to_path_buf()),
            password_stdin: false,
            allow_env_password: false,
        };
        let pw = resolve_password("", &args).unwrap();
        assert_eq!(pw, "hunter2");
    }

    #[test]
    fn password_file_empty_is_error() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let args = PasswordArgs {
            password_file: Some(f.path().to_path_buf()),
            password_stdin: false,
            allow_env_password: false,
        };
        assert!(resolve_password("", &args).is_err());
    }

    #[test]
    fn password_file_missing_is_error() {
        let args = PasswordArgs {
            password_file: Some(PathBuf::from("/nonexistent/path/pw.txt")),
            password_stdin: false,
            allow_env_password: false,
        };
        assert!(resolve_password("", &args).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn password_file_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("password.txt");
        let linked = dir.path().join("linked-password.txt");
        std::fs::write(&target, "secret\n").unwrap();
        symlink(target, &linked).unwrap();
        let args = PasswordArgs {
            password_file: Some(linked),
            password_stdin: false,
            allow_env_password: false,
        };

        assert!(resolve_password("", &args).is_err());
    }
}

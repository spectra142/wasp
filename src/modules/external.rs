use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, warn};
use serde::de::DeserializeOwned;
use tokio::process::Command;
use tokio::time::timeout;

/// Check whether an external tool is available on the system.
///
/// Paths containing a directory component must point at an existing file;
/// bare program names are looked up on `PATH` (honouring `PATHEXT` on
/// Windows). Empty paths resolve to `false`.
pub async fn tool_available(path: &Path) -> bool {
    resolve_tool(path).is_some()
}

/// Resolve `path` to the executable that would be run, if any.
pub fn resolve_tool(path: &Path) -> Option<PathBuf> {
    if path.as_os_str().is_empty() {
        return None;
    }

    if path.components().count() > 1 || path.is_absolute() {
        return is_executable(path).then(|| path.to_path_buf());
    }

    let search = std::env::var_os("PATH")?;
    let extensions: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".to_string())
            .split(';')
            .map(|s| s.to_string())
            .chain(std::iter::once(String::new()))
            .collect()
    } else {
        vec![String::new()]
    };

    for dir in std::env::split_paths(&search) {
        for ext in &extensions {
            let mut name = path.as_os_str().to_os_string();
            name.push(ext);
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                debug!("resolved tool {:?} to {:?}", path, candidate);
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// Run an external program with the supplied arguments, killing it if it
/// exceeds `timeout_duration`.
///
/// The command's stdout and stderr are captured. `kill_on_drop` is enabled
/// so the process is cleaned up if the future is dropped.
pub async fn run_tool(program: &Path, args: &[&str], timeout_duration: Duration) -> Result<Output> {
    debug!("running {:?} with args [{}]", program, args.join(", "));

    let mut cmd = Command::new(program);
    cmd.args(args).kill_on_drop(true);

    let output = timeout(timeout_duration, cmd.output())
        .await
        .map_err(|_| anyhow::anyhow!("{:?} timed out after {:?}", program, timeout_duration))?
        .with_context(|| format!("failed to execute {:?}", program))?;

    Ok(output)
}

/// Parse newline-delimited JSON (NDJSON) output into a vector of `T`.
///
/// Blank lines are ignored and unparseable lines are logged at debug level
/// and skipped. This is useful for tools such as Nuclei, TruffleHog, and
/// GitLeaks that emit one JSON object per line.
pub fn parse_json_lines<T: DeserializeOwned>(text: &str) -> Vec<T> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| match serde_json::from_str::<T>(line) {
            Ok(item) => Some(item),
            Err(e) => {
                warn!("failed to parse JSON line: {} | line: {}", e, line);
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[tokio::test]
    async fn tool_available_finds_sh() {
        assert!(tool_available(Path::new("/bin/sh")).await);
    }

    #[tokio::test]
    async fn tool_available_false_for_missing_file() {
        assert!(!tool_available(Path::new("/definitely/not/a/tool")).await);
    }

    #[tokio::test]
    async fn tool_available_searches_path() {
        assert!(tool_available(Path::new("sh")).await);
        assert!(!tool_available(Path::new("definitely-not-a-real-tool-xyz")).await);
    }

    #[tokio::test]
    async fn tool_available_false_for_empty_path() {
        assert!(!tool_available(Path::new("")).await);
    }

    #[tokio::test]
    async fn run_tool_runs_echo() {
        let output = run_tool(
            Path::new("echo"),
            &["hello", "world"],
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "hello world"
        );
    }

    #[tokio::test]
    async fn run_tool_times_out() {
        let result = run_tool(Path::new("sleep"), &["10"], Duration::from_millis(50)).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Sample {
        id: u32,
        name: String,
    }

    #[test]
    fn parse_json_lines_parses_valid_lines() {
        let input = r#"{"id":1,"name":"one"}
{"id":2,"name":"two"}
"#;
        let parsed: Vec<Sample> = parse_json_lines(input);
        assert_eq!(
            parsed,
            vec![
                Sample {
                    id: 1,
                    name: "one".into()
                },
                Sample {
                    id: 2,
                    name: "two".into()
                },
            ]
        );
    }

    #[test]
    fn parse_json_lines_skips_blank_and_invalid_lines() {
        let input = r#"{"id":1,"name":"one"}
not json
{"id":3,"name":"three"}
"#;
        let parsed: Vec<Sample> = parse_json_lines(input);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, 1);
        assert_eq!(parsed[1].id, 3);
    }
}

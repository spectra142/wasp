use crate::finding::Report;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub fn write(report: &Report, path: &Path) -> Result<()> {
    let json =
        serde_json::to_string_pretty(report).context("failed to serialize report to JSON")?;
    fs::write(path, json).with_context(|| format!("failed to write JSON report to {:?}", path))?;
    Ok(())
}

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp_unix: u64,
    pub actor: String,
    pub action: String,
    pub subject: String,
    pub detail: String,
}

impl AuditEvent {
    pub fn new(actor: &str, action: &str, subject: &str, detail: &str) -> Self {
        let timestamp_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        AuditEvent {
            timestamp_unix,
            actor: actor.to_string(),
            action: action.to_string(),
            subject: subject.to_string(),
            detail: detail.to_string(),
        }
    }
}

/// Append-only, newline-delimited JSON audit log. By construction this
/// module never receives key material or plaintext; callers must only
/// ever pass metadata (who did what to which named subject, and why).
pub struct AuditLog {
    path: std::path::PathBuf,
}

impl AuditLog {
    pub fn open(path: impl AsRef<Path>) -> Self {
        AuditLog {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn record(&self, event: AuditEvent) -> Result<(), AuditError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(&event)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }

    pub fn read_all(&self) -> Result<Vec<AuditEvent>, AuditError> {
        if !self.path.exists() {
            return Ok(vec![]);
        }
        let file = std::fs::File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            events.push(serde_json::from_str(&line)?);
        }
        Ok(events)
    }
}

// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Estruturas dos relatórios JSON (por arquivo e agregados).

use crate::validators::ValidatorOutcome;
use serde::Serialize;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

/// Relatório por arquivo conforme SPEC.
#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub version: String,
    pub generated_at: String,
    pub file: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
    pub sniff: SniffReport,
    pub validators: Vec<ValidatorEntry>,
    pub policy: PolicyDecision,
    pub timings_ms: TimingBreakdown,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub notes: Vec<String>,
}

impl FileReport {
    pub fn new(file: &Path, size_bytes: u64, sha256: String, sniff: SniffReport) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            generated_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            file: file.to_path_buf(),
            size_bytes,
            sha256,
            sniff,
            validators: Vec::new(),
            policy: PolicyDecision::default(),
            timings_ms: TimingBreakdown::default(),
            notes: Vec::new(),
        }
    }
}

/// Resumo agregado conforme SPEC.
#[derive(Debug, Default, Clone, Serialize)]
pub struct SummaryReport {
    pub scanned: u64,
    pub allow: u64,
    pub warn: u64,
    pub deny: u64,
}

impl SummaryReport {
    pub fn update(&mut self, decision: &PolicyDecision) {
        self.scanned += 1;
        match decision.decision.as_str() {
            "ALLOW" => self.allow += 1,
            "WARN" => self.warn += 1,
            "DENY" => self.deny += 1,
            _ => {}
        }
    }
}

/// Estrutura do bloco `sniff` do relatório.
#[derive(Debug, Clone, Serialize)]
pub struct SniffReport {
    pub magic: Option<String>,
    pub mime_real: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_claimed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<String>,
}

impl SniffReport {
    pub fn new(mime_real: String, magic: Option<String>, ext: Option<String>) -> Self {
        Self {
            magic,
            mime_real,
            mime_claimed: None,
            ext,
        }
    }
}

/// Entrada do array `validators`.
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorEntry {
    pub name: String,
    pub status: String,
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub details: serde_json::Value,
}

impl From<&ValidatorOutcome> for ValidatorEntry {
    fn from(outcome: &ValidatorOutcome) -> Self {
        Self {
            name: outcome.name.to_string(),
            status: outcome.status.as_str().to_string(),
            details: outcome.details.clone(),
        }
    }
}

/// Decisão de política que será exibida no relatório.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyDecision {
    pub decision: String,
    #[serde(default)]
    pub rules_triggered: Vec<String>,
}

impl Default for PolicyDecision {
    fn default() -> Self {
        Self {
            decision: "ALLOW".to_string(),
            rules_triggered: Vec::new(),
        }
    }
}

/// Medição de tempo por etapa.
#[derive(Debug, Clone, Serialize, Default)]
pub struct TimingBreakdown {
    pub total: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniff: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validate: Option<f32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_report_initial_state_is_consistent() {
        let sniff = SniffReport::new(
            "application/octet-stream".into(),
            Some("FF".into()),
            Some(".bin".into()),
        );
        let report = FileReport::new(Path::new("sample.bin"), 42, "abcd".into(), sniff.clone());
        assert_eq!(report.file, PathBuf::from("sample.bin"));
        assert_eq!(report.size_bytes, 42);
        assert_eq!(report.sniff.mime_real, "application/octet-stream");
        assert_eq!(report.sniff.magic, Some("FF".into()));
        assert_eq!(report.sniff.ext, Some(".bin".into()));
        assert_eq!(report.policy.decision, "ALLOW");
        assert!(report.validators.is_empty());
        assert!(report.notes.is_empty());
    }

    #[test]
    fn summary_report_counts_by_decision() {
        let mut summary = SummaryReport::default();
        summary.update(&PolicyDecision {
            decision: "ALLOW".into(),
            rules_triggered: vec![],
        });
        summary.update(&PolicyDecision {
            decision: "WARN".into(),
            rules_triggered: vec![],
        });
        summary.update(&PolicyDecision {
            decision: "DENY".into(),
            rules_triggered: vec![],
        });
        assert_eq!(summary.scanned, 3);
        assert_eq!(summary.allow, 1);
        assert_eq!(summary.warn, 1);
        assert_eq!(summary.deny, 1);
    }
}

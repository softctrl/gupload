// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Coordena o pipeline de sniffing, validação e decisão de política.

use crate::cli::FailOn;
use crate::config::PolicyConfig;
use crate::policy::{Decision, DecisionOutcome, PolicyEngine};
use crate::report::{FileReport, PolicyDecision, SniffReport, SummaryReport, ValidatorEntry};
use crate::sniff;
use crate::validators::evaluate_validators;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Responsável por executar o fluxo completo para cada arquivo analisado.
#[derive(Debug, Default)]
pub struct Engine;

/// Campos derivados do subcomando `scan`.
#[derive(Debug)]
pub struct ScanRequest {
    pub paths: Vec<PathBuf>,
    pub policy: Option<PathBuf>,
    pub json: Option<PathBuf>,
    pub summary: Option<PathBuf>,
    pub fail_on: FailOn,
    pub timeout: Option<u64>,
}

/// Resultado do comando `scan`, contendo o código de saída sugerido.
#[derive(Debug)]
pub struct ScanOutcome {
    pub exit_code: i32,
}

/// Requisição para o subcomando `bench` (esqueleto).
#[derive(Debug)]
pub struct BenchRequest {
    pub corpus: PathBuf,
    pub report: Option<PathBuf>,
}

/// Resultado do subcomando `bench`.
#[derive(Debug)]
pub struct BenchOutcome {
    pub exit_code: i32,
}

impl Engine {
    /// Cria uma nova instância do motor principal.
    pub fn new() -> Self {
        Self
    }

    /// Executa varredura completa baseada nos caminhos recebidos.
    pub fn scan(&self, mut request: ScanRequest) -> Result<ScanOutcome> {
        let policy_engine = if let Some(ref policy_path) = request.policy {
            let config = PolicyConfig::from_path(policy_path)?;
            Some(PolicyEngine::new(config))
        } else {
            None
        };

        let targets = collect_targets(&request.paths)?;

        let mut summary = SummaryReport::default();
        let mut highest_decision = Decision::Allow;

        let mut json_writer = if let Some(ref json_path) = request.json {
            Some(std::io::BufWriter::new(
                File::create(json_path).with_context(|| {
                    format!(
                        "não foi possível criar arquivo JSON {}",
                        json_path.display()
                    )
                })?,
            ))
        } else {
            None
        };

        for target in targets {
            match process_file(&target, policy_engine.as_ref()) {
                Ok((mut report, outcome)) => {
                    highest_decision = compare_decision(highest_decision, outcome.decision);
                    let policy_decision: PolicyDecision = outcome.clone().into();
                    summary.update(&policy_decision);
                    report.policy = policy_decision;

                    tracing::debug!(
                        file = %target.display(),
                        decision = %report.policy.decision,
                        size_bytes = report.size_bytes,
                        mime = %report.sniff.mime_real,
                        rules = ?report.policy.rules_triggered,
                        "arquivo analisado"
                    );

                    if let Some(writer) = json_writer.as_mut() {
                        serde_json::to_writer(&mut *writer, &report)?;
                        writer.write_all(b"\n")?;
                        writer.flush()?;
                    } else {
                        let line = serde_json::to_string(&report)?;
                        println!("{line}");
                    }
                }
                Err(err) => {
                    tracing::error!(file = ?target, "falha ao processar arquivo: {err:?}");
                    // Tratamos erro operacional como decisão DENY para respeitar fail_on.
                    highest_decision = Decision::Deny;
                }
            }
        }

        if let Some(summary_path) = request.summary.take() {
            let mut writer =
                std::io::BufWriter::new(File::create(&summary_path).with_context(|| {
                    format!("não foi possível criar summary {}", summary_path.display())
                })?);
            serde_json::to_writer_pretty(&mut writer, &summary)?;
            writer.flush()?;
        }

        let exit_code = compute_exit_code(request.fail_on, highest_decision);
        Ok(ScanOutcome { exit_code })
    }

    /// Esqueleto do comando `bench`, ainda não implementado.
    pub fn bench(&self, request: BenchRequest) -> Result<BenchOutcome> {
        tracing::warn!(
            corpus = %request.corpus.display(),
            "bench ainda não implementado — retornando exit code 0"
        );
        Ok(BenchOutcome { exit_code: 0 })
    }
}

fn collect_targets(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut targets = Vec::new();
    for path in paths {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("não foi possível acessar {}", path.display()))?;
        if metadata.is_file() {
            targets.push(path.clone());
        } else if metadata.is_dir() {
            for entry in WalkDir::new(path) {
                let entry = entry?;
                if entry.file_type().is_file() {
                    targets.push(entry.into_path());
                }
            }
        } else {
            tracing::warn!(target = %path.display(), "ignorado (não é arquivo nem diretório)");
        }
    }
    Ok(targets)
}

fn process_file(
    path: &Path,
    policy_engine: Option<&PolicyEngine>,
) -> Result<(FileReport, DecisionOutcome)> {
    let file = File::open(path).with_context(|| format!("falha ao abrir {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;

    let size_bytes = buffer.len() as u64;
    let digest = Sha256::digest(&buffer);
    let sha256 = hex::encode(digest);

    let sniff_result = sniff::sniff_bytes(&buffer)?;
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| format!(".{}", s.to_ascii_lowercase()));
    let sniff_report = SniffReport::new(sniff_result.mime_real, sniff_result.magic, ext);

    let mut report = FileReport::new(path, size_bytes, sha256, sniff_report);

    let resolved_policy = policy_engine.map(|engine| engine.resolve(&report));
    let resolved_policy_ref = resolved_policy.as_ref();
    let validator_outcomes = evaluate_validators(
        report.sniff.mime_real.as_str(),
        &buffer,
        resolved_policy_ref,
    );
    report.validators = validator_outcomes
        .iter()
        .map(ValidatorEntry::from)
        .collect();

    let outcome = if let Some(engine) = policy_engine {
        engine.decide(&report, &validator_outcomes, resolved_policy_ref)
    } else {
        DecisionOutcome::new()
    };

    Ok((report, outcome))
}

fn compare_decision(current: Decision, candidate: Decision) -> Decision {
    if candidate.severity() > current.severity() {
        candidate
    } else {
        current
    }
}

fn compute_exit_code(fail_on: FailOn, decision: Decision) -> i32 {
    let threshold = match fail_on {
        FailOn::Error => 3,
        FailOn::Warn => 1,
        FailOn::Deny => 2,
    };

    let severity_value = decision.severity();
    if severity_value >= threshold {
        match decision {
            Decision::Deny => 1,
            Decision::Warn => 3,
            Decision::Allow => 0,
        }
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn compute_exit_code_respects_fail_on() {
        assert_eq!(compute_exit_code(FailOn::Deny, Decision::Allow), 0);
        assert_eq!(compute_exit_code(FailOn::Warn, Decision::Warn), 3);
        assert_eq!(compute_exit_code(FailOn::Deny, Decision::Deny), 1);
        assert_eq!(compute_exit_code(FailOn::Error, Decision::Warn), 0);
    }

    #[test]
    fn collect_targets_handles_files_and_directories() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        let file_a = root.join("a.txt");
        let nested_dir = root.join("nested");
        std::fs::create_dir_all(&nested_dir).expect("create nested");
        let file_b = nested_dir.join("b.txt");
        std::fs::write(&file_a, b"alpha").expect("write a");
        std::fs::write(&file_b, b"beta").expect("write b");

        let mut targets = collect_targets(&[root.to_path_buf()]).expect("collect");
        targets.sort();
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&file_a));
        assert!(targets.contains(&file_b));
    }

    #[test]
    fn compare_decision_picks_highest_severity() {
        assert_eq!(
            compare_decision(Decision::Allow, Decision::Warn),
            Decision::Warn
        );
        assert_eq!(
            compare_decision(Decision::Warn, Decision::Allow),
            Decision::Warn
        );
        assert_eq!(
            compare_decision(Decision::Warn, Decision::Deny),
            Decision::Deny
        );
    }
}

// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Validador básico de arquivos ZIP.

use super::ValidatorOutcome;
use crate::config::ArchivePolicySection;
use crate::policy::ResolvedPolicy;
use serde_json::json;
use std::io::Cursor;
use zip::read::ZipFile;
use zip::ZipArchive;

pub fn validate_archive(
    mime: &str,
    data: &[u8],
    policy: Option<&ResolvedPolicy>,
) -> ValidatorOutcome {
    let name = "archive";
    let archive_policy = policy.map(|p| p.archive.clone()).unwrap_or_default();
    let cursor = Cursor::new(data);

    let mut archive = match ZipArchive::new(cursor) {
        Ok(archive) => archive,
        Err(err) => {
            return ValidatorOutcome::deny(name, format!("arquivo ZIP inválido ({mime}): {err}"))
        }
    };

    let mut issues = Vec::new();
    let mut total_ratio = 0.0f64;
    let mut worst_ratio = 0.0f64;
    let mut file_count = 0usize;

    for i in 0..archive.len() {
        let file = match archive.by_index(i) {
            Ok(file) => file,
            Err(err) => {
                return ValidatorOutcome::deny(name, format!("falha ao ler entrada do ZIP: {err}"))
            }
        };
        file_count += 1;

        if violates_entry(&file, &archive_policy, &mut issues) {
            return ValidatorOutcome::deny(name, issues.join("; "));
        }

        if let Some(ratio) = compression_ratio(&file) {
            total_ratio += ratio;
            if ratio > worst_ratio {
                worst_ratio = ratio;
            }
            if let Some(max_ratio) = archive_policy.zip_max_ratio {
                if ratio > max_ratio as f64 {
                    return ValidatorOutcome::deny(
                        name,
                        format!(
                            "entrada '{}' excede zip_max_ratio (ratio={ratio:.2} > {max_ratio})",
                            file.name()
                        ),
                    );
                }
            }
        }

        if let Some(max_depth) = archive_policy.zip_max_depth {
            let depth = depth_of(file.name());
            if depth > max_depth as usize {
                return ValidatorOutcome::deny(
                    name,
                    format!(
                        "profundidade excede limite ({depth} > {max_depth}) na entrada '{}'",
                        file.name()
                    ),
                );
            }
        }
    }

    let mut outcome = ValidatorOutcome::pass(name);
    outcome.details = json!({
        "mime": mime,
        "entries": file_count,
        "avg_ratio": if file_count > 0 {
            Some(total_ratio / file_count as f64)
        } else {
            None
        },
        "worst_ratio": if file_count > 0 { Some(worst_ratio) } else { None },
    });
    outcome
}

fn violates_entry(
    file: &ZipFile<'_>,
    policy: &ArchivePolicySection,
    issues: &mut Vec<String>,
) -> bool {
    if policy.forbid_path_traversal.unwrap_or(true) && file.enclosed_name().is_none() {
        issues.push(format!("entrada '{}' possui path traversal", file.name()));
        return true;
    }

    if policy.forbid_symlinks.unwrap_or(true) {
        if let Some(mode) = file.unix_mode() {
            if is_symlink(mode) {
                issues.push(format!("entrada '{}' é symlink não permitido", file.name()));
                return true;
            }
        }
    }

    false
}

fn compression_ratio(file: &ZipFile<'_>) -> Option<f64> {
    let compressed = file.compressed_size() as f64;
    let uncompressed = file.size() as f64;
    if uncompressed == 0.0 {
        return Some(1.0);
    }
    if compressed == 0.0 {
        return Some(f64::INFINITY);
    }
    Some(uncompressed / compressed)
}

fn depth_of(name: &str) -> usize {
    name.trim_end_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count()
}

fn is_symlink(unix_mode: u32) -> bool {
    (unix_mode & 0o170000) == 0o120000
}

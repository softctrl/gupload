// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Validador básico de PDFs.

use super::ValidatorOutcome;
use crate::policy::ResolvedPolicy;
use serde_json::json;

pub fn validate_pdf(data: &[u8], policy: Option<&ResolvedPolicy>) -> ValidatorOutcome {
    let name = "pdf";
    if data.len() < 8 || !data.starts_with(b"%PDF-") {
        return ValidatorOutcome::deny(name, "arquivo não possui header %PDF- válido");
    }

    let pdf_policy = policy.map(|p| p.pdf.clone()).unwrap_or_default();
    let mut details = json!({
        "size_bytes": data.len(),
    });

    let page_count = count_occurrences(data, b"/Type /Page");
    details["page_count"] = json!(page_count);

    if let Some(max_pages) = pdf_policy.max_pages {
        if page_count as u32 > max_pages {
            return ValidatorOutcome::deny(
                name,
                format!("PDF excede limite de páginas: {page_count} > {max_pages}"),
            );
        }
    }

    if pdf_policy.allow_javascript != Some(true)
        && (contains_case_insensitive(data, b"/JavaScript")
            || contains_case_insensitive(data, b"/JS"))
    {
        return ValidatorOutcome::deny(name, "JavaScript detectado em PDF");
    }

    if pdf_policy.forbid_embedded_files.unwrap_or(true)
        && contains_case_insensitive(data, b"/EmbeddedFiles")
    {
        return ValidatorOutcome::deny(name, "PDF possui EmbeddedFiles não permitidos");
    }

    let mut outcome = ValidatorOutcome::pass(name);
    outcome.details = details;
    outcome
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| eq_ascii_case(window, needle))
        .count()
}

fn contains_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| eq_ascii_case(window, needle))
}

fn eq_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

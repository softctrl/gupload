// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Validador genérico — placeholder para conteúdo não especializado.

use super::ValidatorOutcome;
use crate::policy::ResolvedPolicy;
use serde_json::json;

pub fn validate_generic(
    _mime: &str,
    data: &[u8],
    _policy: Option<&ResolvedPolicy>,
) -> ValidatorOutcome {
    let mut outcome = ValidatorOutcome::pass("generic");
    outcome.details = json!({ "size_bytes": data.len() });
    outcome
}

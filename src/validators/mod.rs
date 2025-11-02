// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Conjunto de validadores específicos por tipo de conteúdo.

mod archive;
mod generic;
mod image;
mod pdf;

use crate::policy::ResolvedPolicy;
use serde_json::{json, Value};

pub use archive::validate_archive;
pub use generic::validate_generic;
pub use image::validate_image;
pub use pdf::validate_pdf;

/// Resultado padrão devolvido pelos validadores.
#[derive(Debug, Clone)]
pub struct ValidatorOutcome {
    pub name: &'static str,
    pub status: ValidatorStatus,
    pub details: Value,
}

impl ValidatorOutcome {
    pub fn new(name: &'static str, status: ValidatorStatus, details: Value) -> Self {
        Self {
            name,
            status,
            details,
        }
    }

    pub fn pass(name: &'static str) -> Self {
        Self::new(name, ValidatorStatus::Pass, Value::Null)
    }

    pub fn warn(name: &'static str, message: impl Into<String>) -> Self {
        Self::new(
            name,
            ValidatorStatus::Warn,
            json!({ "message": message.into() }),
        )
    }

    pub fn deny(name: &'static str, message: impl Into<String>) -> Self {
        Self::new(
            name,
            ValidatorStatus::Deny,
            json!({ "message": message.into() }),
        )
    }

    pub fn error(name: &'static str, message: impl Into<String>) -> Self {
        Self::new(
            name,
            ValidatorStatus::Error,
            json!({ "message": message.into() }),
        )
    }
}

/// Estado da validação conforme schema do relatório.
#[derive(Debug, Clone, Copy)]
pub enum ValidatorStatus {
    Pass,
    Warn,
    Deny,
    Error,
}

impl ValidatorStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ValidatorStatus::Pass => "pass",
            ValidatorStatus::Warn => "warn",
            ValidatorStatus::Deny => "deny",
            ValidatorStatus::Error => "error",
        }
    }
}

/// Executa validadores com base no MIME real do arquivo.
pub fn evaluate_validators(
    mime: &str,
    data: &[u8],
    policy: Option<&ResolvedPolicy>,
) -> Vec<ValidatorOutcome> {
    let mut outcomes = Vec::new();

    if mime.starts_with("image/") {
        outcomes.push(validate_image(mime, data, policy));
    } else if mime == "application/pdf" {
        outcomes.push(validate_pdf(data, policy));
    } else if matches!(
        mime,
        "application/zip"
            | "application/x-zip-compressed"
            | "application/x-zip"
            | "multipart/x-zip"
    ) {
        outcomes.push(validate_archive(mime, data, policy));
    } else {
        outcomes.push(validate_generic(mime, data, policy));
    }

    outcomes
}

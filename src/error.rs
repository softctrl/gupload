// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Tipos de erro estruturados do GuardUpload.

use thiserror::Error;

/// Categorias de erro alinhadas aos códigos de saída definidos.
#[derive(Debug, Error)]
pub enum GuardUploadError {
    /// Representa falhas operacionais (I/O, timeouts etc.).
    #[error("erro operacional: {0}")]
    Operational(String),
    /// Configuração de política inválida.
    #[error("política inválida: {0}")]
    PolicyInvalid(String),
    /// Erro genérico abrangendo outras situações.
    #[error("{0}")]
    Generic(String),
}

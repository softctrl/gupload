// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Gestão de limites de tempo, memória e entropia.

/// Parâmetros de limites globais para aplicarmos no pipeline.
#[derive(Debug, Default, Clone)]
pub struct LimitSettings {
    /// Timeout máximo (em segundos) para processar um arquivo.
    pub timeout_secs: Option<u64>,
    /// Entropia máxima permitida antes de disparar WARN/DENY.
    pub entropy_threshold: Option<f32>,
}

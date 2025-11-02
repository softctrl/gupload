// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Analisadores auxiliares (entropia, estatísticas estruturais).

/// Estrutura para resultados de análise de entropia.
#[derive(Debug, Clone)]
pub struct EntropyAnalysis {
    pub entropy: f32,
    pub window_size: usize,
}

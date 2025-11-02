// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Sniff de MIME real baseado em magic bytes e heurísticas.

use anyhow::Result;
use tree_magic_mini::from_u8;

/// Resultado mínimo do sniff para integrar com o pipeline.
#[derive(Debug, Clone)]
pub struct SniffResult {
    pub mime_real: String,
    pub magic: Option<String>,
}

/// Detecta MIME utilizando `tree_magic_mini`.
pub fn sniff_bytes(data: &[u8]) -> Result<SniffResult> {
    let mime = from_u8(data).to_string();
    let magic = data.get(0..8).map(|slice| {
        slice
            .iter()
            .map(|byte| format!("{:02X}", byte))
            .collect::<Vec<_>>()
            .join(" ")
    });
    Ok(SniffResult {
        mime_real: mime,
        magic,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_bytes_detects_text_plain() {
        let data = b"Hello world\n";
        let result = sniff_bytes(data).expect("sniff should succeed");
        assert_eq!(result.mime_real, "text/plain");
        assert_eq!(result.magic.as_deref(), Some("48 65 6C 6C 6F 20 77 6F"));
    }
}

// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Carregamento e validação de configurações de política em YAML.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;

/// Configuração raiz carregada a partir do YAML de políticas.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConfig {
    #[serde(default)]
    pub defaults: DefaultsSection,
    #[serde(default)]
    pub pdf: PdfPolicySection,
    #[serde(default)]
    pub image: ImagePolicySection,
    #[serde(default)]
    pub archive: ArchivePolicySection,
    #[serde(default)]
    pub overrides: Vec<PolicyOverride>,
}

impl PolicyConfig {
    /// Carrega o YAML de política a partir de um caminho.
    pub fn from_path(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("falha ao abrir política: {}", path.display()))?;
        let config: PolicyConfig = serde_yaml::from_reader(file)
            .with_context(|| format!("falha ao parsear YAML {}", path.display()))?;
        Ok(config)
    }
}

/// Valores padrão aplicados a todos os tipos.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DefaultsSection {
    pub max_size_mb: Option<u32>,
    #[serde(default)]
    pub allow_types: Vec<String>,
    #[serde(default)]
    pub deny_types: Vec<String>,
    #[serde(default)]
    pub entropy_threshold: Option<f32>,
    #[serde(default)]
    pub fail_on: Option<String>,
}

/// Política específica para PDFs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfPolicySection {
    pub allow_javascript: Option<bool>,
    pub max_pages: Option<u32>,
    pub forbid_embedded_files: Option<bool>,
}

impl Default for PdfPolicySection {
    fn default() -> Self {
        Self {
            allow_javascript: Some(false),
            max_pages: Some(200),
            forbid_embedded_files: Some(true),
        }
    }
}

/// Política específica para imagens.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImagePolicySection {
    pub max_dimensions: Option<[u32; 2]>,
    pub max_frames: Option<u32>,
    pub strip_metadata: Option<String>,
}

/// Política específica para arquivos compactados.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArchivePolicySection {
    pub zip_max_depth: Option<u32>,
    pub zip_max_ratio: Option<u32>,
    pub forbid_symlinks: Option<bool>,
    pub forbid_path_traversal: Option<bool>,
}

/// Regras condicionais para ajustes finos da política.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyOverride {
    #[serde(default)]
    pub if_mime: Option<Vec<String>>,
    #[serde(default)]
    pub if_source: Option<String>,
    #[serde(default)]
    pub set: BTreeMap<String, Value>,
}

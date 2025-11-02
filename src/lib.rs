// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! GuardUpload — biblioteca principal do utilitário CLI.
//!
//! Este crate organiza a CLI, carregamento de políticas, sniffing de MIME,
//! validações e geração de relatórios conforme os requisitos do SPEC.

pub mod analyzers;
pub mod cli;
pub mod config;
pub mod engine;
pub mod error;
pub mod limits;
pub mod policy;
pub mod report;
pub mod sniff;
pub mod validators;

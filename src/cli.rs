// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Camada de interface de linha de comando baseada em `clap`.

use crate::engine::{BenchOutcome, BenchRequest, Engine, ScanOutcome, ScanRequest};
use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Objeto auxiliar para executar a CLI.
pub struct GuardUploadCli;

/// Estrutura raiz da CLI (com subcomandos).
#[derive(Debug, Parser)]
#[command(
    name = "guardupload",
    version,
    about = "GuardUpload — validação segura de uploads"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Conjunto de subcomandos disponíveis.
#[derive(Debug, Subcommand)]
enum Commands {
    /// Executa varredura em arquivos, diretórios ou stdin.
    Scan(ScanArgs),
    /// Executa medições de benchmark (stub inicial).
    Bench(BenchArgs),
}

/// Opções do subcomando `scan`.
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Caminhos de arquivos ou diretórios a serem verificados.
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,

    /// Caminho para o arquivo de política YAML.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Caminho para salvar o relatório JSONL detalhado.
    #[arg(long)]
    pub json: Option<PathBuf>,

    /// Caminho para salvar o resumo agregado.
    #[arg(long)]
    pub summary: Option<PathBuf>,

    /// Ação quando encontrar WARN/DENY/ERROR.
    #[arg(long, value_enum, default_value = "deny")]
    pub fail_on: FailOn,

    /// Limite de tempo por arquivo.
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Nível de log global.
    #[arg(long, value_enum, default_value = "info")]
    pub log_level: LogLevel,
}

/// Opções do subcomando `bench`.
#[derive(Debug, Args)]
pub struct BenchArgs {
    /// Caminho para corpus rotulado.
    #[arg(long)]
    pub corpus: PathBuf,

    /// Caminho do relatório de benchmark.
    #[arg(long)]
    pub report: Option<PathBuf>,
}

/// Representa as escolhas do parâmetro --fail-on.
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum)]
pub enum FailOn {
    Deny,
    Warn,
    Error,
}

/// Representa os níveis de log aceitos pela CLI.
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for tracing::Level {
    fn from(level: LogLevel) -> tracing::Level {
        match level {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    }
}

impl GuardUploadCli {
    /// Analisa argumentos, inicializa observabilidade e delega ao engine.
    pub fn run() -> Result<i32> {
        let cli = Cli::parse();

        let log_level = cli.scan_log_level();
        configure_logging(log_level);

        let engine = Engine::new();
        let exit_code = match cli.command {
            Commands::Scan(args) => {
                let request = ScanRequest::from(args);
                let outcome: ScanOutcome = engine.scan(request)?;
                outcome.exit_code
            }
            Commands::Bench(args) => {
                let request = BenchRequest::from(args);
                let outcome: BenchOutcome = engine.bench(request)?;
                outcome.exit_code
            }
        };
        Ok(exit_code)
    }
}

impl Cli {
    fn scan_log_level(&self) -> LogLevel {
        match &self.command {
            Commands::Scan(args) => args.log_level,
            Commands::Bench(_) => LogLevel::Info,
        }
    }
}

fn configure_logging(level: LogLevel) {
    use tracing_subscriber::fmt::format::FmtSpan;
    let lvl: tracing::Level = level.into();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(lvl)
        .json()
        .with_span_events(FmtSpan::ENTER | FmtSpan::EXIT)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

impl From<ScanArgs> for ScanRequest {
    fn from(args: ScanArgs) -> Self {
        Self {
            paths: args.paths,
            policy: args.policy,
            json: args.json,
            summary: args.summary,
            fail_on: args.fail_on,
            timeout: args.timeout,
        }
    }
}

impl From<BenchArgs> for BenchRequest {
    fn from(args: BenchArgs) -> Self {
        Self {
            corpus: args.corpus,
            report: args.report,
        }
    }
}

#!/usr/bin/env bash
# GuardUpload
# Criado em: 2025-11-01
# Licença: MIT
# Empresa: SoftCtrl

# Configura o ambiente de desenvolvimento local para o GuardUpload.
# Requisitos: bash, curl e rustup (ou acesso à internet para instalá-lo).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

info() {
  printf '\033[1;32m[INFO]\033[0m %s\n' "$*"
}

warn() {
  printf '\033[1;33m[WARN]\033[0m %s\n' "$*"
}

ensure_rustup() {
  if command -v rustup >/dev/null 2>&1; then
    info "rustup encontrado."
    return
  fi

  warn "rustup não encontrado. Tentando instalação automática (requer internet)."
  if command -v curl >/dev/null 2>&1; then
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    export PATH="$HOME/.cargo/bin:$PATH"
    info "rustup instalado."
  else
    warn "curl indisponível. Instale rustup manualmente: https://rustup.rs"
    exit 1
  fi
}

ensure_rust_toolchain() {
  info "Instalando toolchain Rust estável (profile=minimal)."
  rustup toolchain install stable --profile minimal
  rustup default stable
  rustup component add rustfmt clippy
}

ensure_cargo_binary() {
  local crate="$1"
  if command -v "$crate" >/dev/null 2>&1; then
    info "$crate já instalado."
    return
  fi
  info "Instalando $crate."
  cargo install "$crate" --locked
}

prime_cache() {
  info "Baixando dependências do projeto (cargo fetch)."
  cargo fetch --manifest-path "$ROOT_DIR/Cargo.toml"
}

main() {
  info "Iniciando setup do GuardUpload."
  ensure_rustup
  ensure_rust_toolchain

  if command -v cargo >/dev/null 2>&1; then
    ensure_cargo_binary cargo-audit || warn "Falha opcional ao instalar cargo-audit."
    ensure_cargo_binary cargo-outdated || warn "Falha opcional ao instalar cargo-outdated."
  else
    warn "cargo não encontrado (verifique instalação do rustup)."
  fi

  prime_cache || warn "Não foi possível pré-baixar dependências (verifique conexão)."

  info "Setup concluído. Execute 'make check' para validar."
}

main "$@"

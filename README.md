# GuardUpload

GuardUpload é um utilitário de linha de comando escrito em Rust para validar uploads com foco em segurança, performance e governança de políticas. 

## Visão Geral

- **Entrada**: arquivos individuais, diretórios (recursivo) ou stdin (ainda em planejamento).
- **Processamento**: sniff de MIME real via `tree_magic_mini`, cálculo de hash, estrutura de relatório alinhada ao SPEC, integração com política YAML (esqueleto).
- **Saída**: JSON por arquivo (stdout ou `--json`) e resumo opcional (`--summary`), além de códigos de saída determinísticos.
- **Extensibilidade**: módulos independentes (`sniff`, `validators`, `policy`, `report`, etc.) para evoluir validadores específicos (PDF, imagens, ZIP) e lógica de políticas.

## Requisitos

- Rust 1.76+ (edition 2021).
- Ferramentas padrão `cargo`, `rustfmt` e `clippy`.
- Opcional: `cargo-audit` e `cargo-fuzz` (planejado).

### Configuração rápida

```bash
./scripts/setup.sh
```

O script garante Rust estável, componentes (`rustfmt`, `clippy`) e utilitários opcionais (`cargo-audit`, `cargo-outdated`), além de baixar dependências para uso offline.

## Como usar (versão inicial)

```bash
cargo run -- scan ./amostras \
  --policy policy.yaml \
  --json out.jsonl \
  --summary summary.json \
  --log-level debug
```

### Subcomandos

- `scan <paths...>`: processa arquivos/diretórios, gera relatórios e aplica política.
  - `--policy <arquivo>`: arquivo YAML com políticas, conforme SPEC.
  - `--json <arquivo>`: grava cada relatório em JSON Lines.
  - `--summary <arquivo>`: grava resumo agregado em JSON.
  - `--fail-on <deny|warn|error>`: controla severidade que provoca código de saída diferente de zero.
  - `--log-level <trace|debug|info|warn|error>`: nível de logging estruturado (JSON).
- `bench`: esqueleto para métricas de desempenho/qualidade (to-do).

## Estrutura do Projeto

- `src/cli.rs`: parsing de argumentos (Clap) e roteamento de subcomandos.
- `src/engine.rs`: pipeline principal (coleta de arquivos, sniff, relatório, política).
- `src/policy.rs`: motor de políticas (stub, pronto para expansão).
- `src/report.rs`: schemas de relatório (arquivo e resumo).
- `src/sniff.rs`: sniff de MIME via `tree_magic_mini`.
- `src/validators/`: lugar para validadores por tipo de arquivo.
- `BACKLOG.md`: backlog vivo com itens priorizados.

## Roadmap Imediato

Consulte `BACKLOG.md` para o detalhamento. Principais próximos passos:

1. Implementar validadores profundos (PDF, imagem, ZIP) com limites e sanitização.
2. Expandir motor de políticas com merges/overrides e falhas determinísticas.
3. Adicionar modo `bench` com métricas (FP/FN, P95, cobertura).
4. Integrar limites (timeout/memória) e sandbox opcional.
5. Evoluir relatórios (schema formal, métricas adicionais, `by_mime`).

## Licença

MIT © SoftCtrl. Veja `LICENSE` para detalhes.

## Contribuição

- Mantenha os cabeçalhos dos arquivos conforme padrão (data, licença, empresa).
- Atualize `BACKLOG.md` a cada incremento significativo.
- Garanta que o CI (GitHub Actions) permaneça verde (`cargo fmt`, `cargo clippy`, `cargo test`).

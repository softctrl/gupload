# GuardUpload — Arquitetura (v0.1)

## Visão Geral

O GuardUpload é organizado em módulos Rust claramente separados para favorecer extensibilidade e segurança. O pipeline segue o diagrama definido no SPEC e atualmente implementa as etapas iniciais (sniff→relatório→política).

```
Entrada (arquivo|diretório) ──▶ Sniffer ──▶ Engine ──▶ Política ──▶ Relatórios/Exit Codes
```

## Módulos Principais

- `cli`: definição dos subcomandos `scan` e `bench` via Clap, configuração de logs (`tracing`) e roteamento para o `engine`.
- `engine`: orquestra o fluxo. Coleta arquivos via `walkdir`, realiza sniff (`sniff`), calcula SHA-256, monta `FileReport`/`SummaryReport` e aplica o `PolicyEngine`.
- `sniff`: encapsula `tree_magic_mini` e gera `SniffResult` (MIME real + magic bytes).
- `report`: guarda os schemas de relatório (arquivo individual + resumo). Facilita serialização JSON compatível com o SPEC.
- `policy`: motor de políticas. Hoje retorna `ALLOW` por padrão, mas já expõe `Decision` e `PolicyEngine` para aplicar as regras descritas no SPEC.
- `config`: leitura do YAML de política (`PolicyConfig`) com estruturas defaultizadas.
- `validators`: ponto de entrada para validadores específicos (PDF, imagens, arquivos compactados). Ainda em stub.
- `limits`, `analyzers`: estruturas auxiliares para limites operacionais e cálculos (entropia, etc.).

## Fluxo `scan`

1. **Entrada**: usuário fornece arquivos/diretórios (`ScanArgs.paths`).
2. **Coleta**: `collect_targets` expande diretórios recursivamente usando `walkdir`.
3. **Sniff**: para cada arquivo, lemos em memória (versão inicial) e identificamos MIME real + magic bytes.
4. **Hash**: calculamos SHA-256 para auditoria / integridade.
5. **Relatório**: montamos `FileReport` obedecendo a estrutura do SPEC.
6. **Política**: `PolicyEngine::decide` (stub) determinará `Decision` e atualizará `SummaryReport`.
7. **Saída**: escrevemos JSONL (stdout ou arquivo) e resumo agregado opcional.
8. **Exit Code**: calculado conforme severidade máxima (`ALLOW|WARN|DENY`) e `--fail-on`.

## Códigos de Saída

- `0` — sucesso (nenhum DENY e, dependendo de `--fail-on`, WARN pode ser considerado sucesso).
- `1` — DENY encontrado.
- `3` — WARN encontrado e `--fail-on warn`.
- `2` — erros operacionais (por padrão mapeados em `main.rs`).
- `4` — reservado para política inválida (a ser integrado juntamente com validações de schema).

## Próximos Passos Arquiteturais

- Integrar validadores especializados (PDF/Imagem/ZIP) com limites estritos.
- Evoluir `PolicyEngine` para aplicar merges/overrides de `PolicyConfig` e mapear regras acionadas.
- Adicionar streaming (evitar carregar arquivos grandes em memória).
- Introduzir sandbox opcional e limites de recursos em `limits`.
- Gerar schema JSON formal (`report/schema.json`) e tests de contract.

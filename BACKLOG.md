## GuardUpload Backlog (Sprint 0)

### Concluído (Sprint 0)
- Esqueleto da CLI (`scan`, `bench` stub), engine e geração inicial de relatórios.
- Configuração base de logging estruturado e cálculo SHA-256/sniff MIME.
- Motor de políticas básico (allow/deny e limite de tamanho).

### Prioridade Alta
- Definir schema final dos relatórios (`report/schema.json`) e implementar serialização JSON.
- Implementar sniffer de MIME real com `tree_magic_mini` e heurísticas adicionais por extensão.
- Construir motor de políticas com suporte a merges e overrides definidos no SPEC.
- Desenvolver validadores de PDF, imagem e arquivos compactados conforme requisitos de segurança.
- Implementar limites de tamanho, entropia e timeouts.
- Preparar CLI `scan` para processar arquivos/dirs/stdin gerando `out.jsonl` e `summary.json`.

### Prioridade Média
- Implementar subcomando `bench` com métricas de FP/FN e tempos.
- Adicionar stripping de metadados de imagem conforme política (`warn`/`deny`).
- Integrar cálculos de entropia com janelas configuráveis.
- Suporte a sandbox opcional para parsers custosos.
- Construir modo streaming com hashing SHA-256 incremental.

### Prioridade Baixa / Roadmap
- Suporte a TAR/GZIP além de ZIP.
- Isolamento multi-processo e limites por rlimit.
- Integrações com SBOM, assinatura (cosign) e SCA automatizada.
- Preparar Docker multi-stage e empacotamento cross-platform.
- Pós v1: sanitização SVG, suporte 7z/rar, daemon gRPC, telemetria Prometheus.

# SINTUFCE Sorteios Offline

Aplicativo Windows independente, sem rede e auditável para os sorteios do
SINTUFCE.

## Estado

Fundação em desenvolvimento. O módulo web permanece ativo até a homologação
formal do aplicativo offline.

## Estrutura

- `crates/core`: regras, pacote lacrado, persistência e auditoria.
- `crates/cli`: operação e testes sem interface gráfica.
- `crates/verifier`: verificação independente e somente leitura.
- `apps/desktop`: interface Windows em Tauri.

O protocolo de alto rigor está em
[`docs/architecture/ALGORITHM-v1.md`](docs/architecture/ALGORITHM-v1.md).

Dependências para operação e compilação estão em
[`docs/DEPENDENCIAS.md`](docs/DEPENDENCIAS.md).

## Desenvolvimento

```bash
cargo test --workspace
cargo run -p sintufce-sorteio-cli -- package-inspect arquivo.sintufce
```

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
[`docs/architecture/ALGORITHM-v2.md`](docs/architecture/ALGORITHM-v2.md).

Dependências para operação e compilação estão em
[`docs/DEPENDENCIAS.md`](docs/DEPENDENCIAS.md).

## Desenvolvimento

```bash
cargo test --workspace
cargo run -p sintufce-sorteio-cli -- package-inspect arquivo.sintufce
```

## Eventos locais

A versão 0.2.1 mantém vários eventos no mesmo computador. Use **Meus sorteios** para importar um novo pacote, continuar um evento ou consultar um histórico finalizado. Reimportar o mesmo pacote abre o evento já salvo. Eventos concluídos permanecem imutáveis.

O arquivo existente `sorteio.db` é preservado no diretório de dados do aplicativo. Novos eventos ficam no subdiretório `events`, um banco por evento. Para backup, preserve o diretório de dados inteiro, inclusive os arquivos WAL/SHM quando o aplicativo estiver aberto; preferencialmente feche o app antes de copiar. As chaves protegidas continuam vinculadas ao usuário do Windows.

Antes do lacre, use **Revisar números** e **Voltar e corrigir**. Após lacrar, os números são imutáveis.

# Protocolo seguro de transferência v1 — plano de implementação

**Objetivo:** Assinar e validar os pacotes de ida e volta, recomputar integralmente o resultado e garantir idempotência sem exigir computador previamente cadastrado.

**Arquitetura:** O núcleo Rust define serialização canônica, limites, assinaturas Ed25519 e pacotes finais. A aplicação Windows cria uma identidade por evento e assina o resultado. A API web emite pacotes com uma chave privada de produção e só importa resultados após validar toda a prova determinística.

**Tecnologias:** Rust, Ed25519, SHA-256, ZIP, SQLite, Node.js `crypto`, Fastify, Prisma/PostgreSQL, React/Tauri.

**Especificação:** `docs/architecture/TRANSFER-PROTOCOL-v1.md`

## Restrições globais

- O computador não é conhecido antecipadamente.
- Nenhuma chave privada entra no repositório ou no instalador.
- Mesmos elegíveis, prêmios e chave Federal sempre produzem os mesmos ganhadores.
- A ordem da planilha não participa do resultado.
- O sorteio continua sem rede.
- Pacotes conflitantes, alterados ou repetidos são rejeitados antes de gravar estado.

## Foco de revisão

- ZIP com nomes duplicados, caminhos absolutos, `..`, links ou expansão acima do limite.
- Manifesto válido com CSV, assinatura, contagem ou hash adulterado.
- Mesma lista em ordens diferentes produzindo resultado diferente.
- Segundo resultado conflitante para evento já finalizado.
- Falha entre validação e commit deixando estado parcial.

### Tarefa 1: Primitivas canônicas e assinaturas

**Arquivos:**
- Criar: `crates/core/src/crypto.rs`
- Criar: `crates/core/tests/crypto_protocol.rs`
- Modificar: `crates/core/src/lib.rs`
- Modificar: `Cargo.toml`
- Modificar: `crates/core/Cargo.toml`

**Interfaces:** `canonical_json`, `domain_message`, `sign_ed25519`, `verify_ed25519`, `sha256_hex`.

- [ ] Escrever vetores fixos para serialização, assinatura válida e adulteração.
- [ ] Executar o teste e confirmar falha pela ausência das interfaces.
- [ ] Implementar as primitivas com `ed25519-dalek` e zeroização de segredo.
- [ ] Executar os testes e confirmar aprovação.
- [ ] Commitar a unidade.

### Tarefa 2: Validação rígida do pacote web

**Arquivos:**
- Modificar: `crates/core/src/package.rs`
- Modificar: `crates/core/tests/package_validation.rs`
- Modificar: `schemas/manifest-v1.schema.json`
- Modificar: `docs/package-format-v1.md`

**Interfaces:** `PackageValidator::validate_reader_with_keys(reader, trusted_keys)` produz `ValidatedPackage` com `package_hash` e `export_nonce`.

- [ ] Criar testes de assinatura, arquivo extra, duplicata, traversal, excesso de tamanho, replay material e UTF-8 inválido.
- [ ] Confirmar que os novos testes falham.
- [ ] Implementar formato v2, chave pública fixada por `keyId`, limites antes da extração e assinatura antes do CSV.
- [ ] Executar toda a suíte do núcleo.
- [ ] Commitar a unidade.

### Tarefa 3: Pacote final assinado e verificador independente

**Arquivos:**
- Criar: `crates/core/src/result_package.rs`
- Criar: `crates/core/tests/result_package.rs`
- Modificar: `crates/verifier/src/main.rs`
- Modificar: `crates/verifier/Cargo.toml`

**Interfaces:** `ResultPackageBuilder::build`, `ResultPackageValidator::validate`, `recompute_result`.

- [ ] Criar testes para pacote final válido, assinatura trocada, auditoria quebrada, ganhador divergente e ordem de entrada alterada.
- [ ] Confirmar falhas iniciais.
- [ ] Implementar manifesto final, assinatura da sessão e recomputação completa.
- [ ] Executar núcleo e verificador contra o mesmo vetor público.
- [ ] Commitar a unidade.

### Tarefa 4: Persistência segura no aplicativo Windows

**Arquivos:**
- Criar: `apps/desktop/src-tauri/src/session_identity.rs`
- Criar: `apps/desktop/src-tauri/src/storage.rs`
- Modificar: `apps/desktop/src-tauri/src/lib.rs`
- Modificar: `apps/desktop/src/App.tsx`
- Modificar: `apps/desktop/src-tauri/Cargo.toml`

**Interfaces:** `SessionIdentity::create_for_event`, `SessionIdentity::sign`, `export_result_package`.

- [ ] Criar testes de identidade por evento, persistência, importação atômica e retomada após interrupção.
- [ ] Implementar chave por evento protegida pelo cofre do Windows, com fallback de teste isolado.
- [ ] Trocar exportação JSON pelo `.sintufce-result` e exibir os códigos curtos de conferência.
- [ ] Validar que nenhum segredo aparece em log, banco aberto ou pacote.
- [ ] Commitar a unidade.

### Tarefa 5: Emissão assinada na plataforma web

**Arquivos:**
- Criar: `sintufce-api/src/modules/raffles/raffle-transfer.crypto.ts`
- Criar: `sintufce-api/src/modules/raffles/raffle-transfer.service.ts`
- Criar: `sintufce-api/src/modules/raffles/raffle-transfer.test.ts`
- Modificar: `sintufce-api/src/modules/raffles/raffles.routes.ts`
- Modificar: `sintufce-api/src/modules/raffles/raffles.service.ts`
- Modificar: `sintufce-api/prisma/schema.prisma`

**Interfaces:** `exportSignedPackage(raffleId, actorId)` e `verifyAndImportResult(raffleId, bytes, actorId)`.

- [ ] Criar testes com chave efêmera apenas no teste para emissão, adulteração, replay e conflito.
- [ ] Implementar assinatura com Node `crypto`, chave privada somente via segredo de produção e chave pública versionada.
- [ ] Persistir nonce, hash do pacote, hash final, estado e responsável em transação.
- [ ] Implementar importação com recomputação completa, idempotência e imutabilidade.
- [ ] Executar typecheck e testes da API.
- [ ] Commitar a unidade.

### Tarefa 6: Fluxo de exportação e retorno na interface web

**Arquivos:**
- Modificar: `sintufce-web/src/pages/raffles/RaffleDetailPage.tsx`
- Modificar: `sintufce-web/src/hooks/useRaffles.ts`

**Interfaces:** download do `.sintufce`, upload do `.sintufce-result`, confirmação e resultado de validação.

- [ ] Criar testes do estado fechado, retorno válido e mensagem de conflito.
- [ ] Implementar ações visíveis apenas às permissões existentes.
- [ ] Mostrar hash curto e confirmação explícita sem expor detalhes criptográficos desnecessários.
- [ ] Executar build e testes do frontend.
- [ ] Commitar a unidade.

### Tarefa 7: Teste cruzado e preparação de release

**Arquivos:**
- Criar: `test-vectors/federal-v2.json`
- Modificar: `README.md`
- Modificar: `docs/architecture/ALGORITHM-v2.md`

**Interfaces:** um vetor único consumido por Rust e TypeScript.

- [ ] Validar cem reordenações dos elegíveis com saída idêntica.
- [ ] Validar adulteração de cada arquivo e repetição do resultado.
- [ ] Executar `cargo test --workspace`, testes Tauri, testes API, typecheck e builds.
- [ ] Auditar o histórico e artefatos contra segredos e arquivos não pertencentes ao programa.
- [ ] Preparar release somente após todas as verificações aprovarem.


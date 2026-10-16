# SINTUFCE Draw Protocol v1

## 1. Objetivo

Este protocolo define um sorteio imparcial, determinístico quando auditado,
resistente a manipulação operacional e reproduzível por um verificador
independente. Nenhuma decisão usa `Math.random`, ponto flutuante, número do
ticket, ordem da planilha ou relógio do computador.

O número aleatório do ticket é apenas identificador visual. A identidade
criptográfica do participante é o UUID v4 do ticket.

## 2. Pré-condições

Antes do lacre:

1. Todos os registros possuem UUID v4 único.
2. `situacao_vinculo` é exatamente `FILIADO`.
3. Tickets, UUIDs e SIAPEs não se repetem.
4. Prêmios possuem ordem única e imutável.
5. O concurso da Loteria Federal, quando usado, é escolhido antes de seu
   resultado e registrado no manifesto.
6. A versão do algoritmo é `SINTUFCE-DRAW-V1`.

## 3. Canonicalização

Participantes são normalizados em UTF-8 NFC e ordenados pelos 16 bytes do UUID,
em ordem lexicográfica crescente. Isso impede influência pela ordem da
planilha, nome, SIAPE ou número do ticket.

Cada registro canônico é formado por campos com tamanho prefixado:

```text
uuid[16] || len(ticket)[4] || ticket_utf8 || len(siape)[4] || siape_utf8
```

O compromisso da lista é:

```text
list_hash = SHA-256(
  "SINTUFCE/ELIGIBLES/V1\0" || count_u64_be || registros_canonicos
)
```

Prêmios são ordenados pelo campo `ordem` e recebem compromisso equivalente com
o domínio `SINTUFCE/PRIZES/V1\0`.

## 4. Entropia com compromisso e revelação

O modo recomendado combina uma fonte pública futura e segredos de auditores.
Se ao menos uma fonte permanecer imprevisível até o lacre, nenhum participante
isolado consegue escolher o resultado.

### 4.1 Fonte pública

Usar os cinco números de um concurso da Loteria Federal definido antes do
resultado. A representação é decimal com seis posições por número:

```text
FEDERAL|concurso_10_digitos|n1_6|n2_6|n3_6|n4_6|n5_6
```

O aplicativo é offline. Dois responsáveis digitam os dados separadamente; os
valores precisam coincidir. A cópia oficial é anexada ao pacote final.

### 4.2 Segredos dos auditores

Três auditores produzem individualmente 256 bits de entropia. O método
preferencial é dado físico: 100 lançamentos de dado de seis faces por auditor,
digitados no aplicativo. Antes da revelação, cada auditor registra:

```text
commit_i = SHA-256(
  "SINTUFCE/AUDITOR-COMMIT/V1\0" || event_uuid || auditor_id || secret_i
)
```

Após o lacre e a publicação dos três compromissos, os segredos são revelados e
verificados. A ausência de um auditor segue a política de quórum definida antes
do evento; nunca pode ser decidida após conhecer os demais segredos.

## 5. Derivação da semente

Entradas são ordenadas por `auditor_id`. A semente de 256 bits é derivada por
HKDF-SHA-256:

```text
salt = SHA-256(
  "SINTUFCE/SALT/V1\0" || event_uuid || list_hash || prizes_hash
)

ikm = federal_canonical || secret_1 || secret_2 || secret_3

seed = HKDF-SHA-256(
  salt,
  ikm,
  info="SINTUFCE/DRAW/V1",
  length=32
)
```

Nenhum campo pode ser omitido silenciosamente. Modos de contingência têm outro
identificador de algoritmo e precisam ser escolhidos antes do lacre.

## 6. Permutação imparcial

O protocolo usa ChaCha20 conforme RFC 8439, chave `seed`, contador inicial zero
e nonce derivado de:

```text
nonce = first_12_bytes(SHA-256("SINTUFCE/NONCE/V1\0" || event_uuid))
```

Os bytes do stream são consumidos como inteiros `u64` little-endian. Para obter
um número uniforme em `[0, bound)`, usa-se rejection sampling:

```text
limit = floor(2^64 / bound) * bound
repetir:
  x = next_u64()
até x < limit
resultado = x mod bound
```

Nunca usar `% bound` sem rejeição, pois introduz viés modular.

Com essa função, aplicar Fisher-Yates de `n-1` até `1`. O resultado é uma
permutação completa e única da lista canônica. A implementação é própria e
versionada; não depende do comportamento interno de bibliotecas de RNG.

## 7. Associação aos prêmios

Prêmios permanecem na ordem previamente lacrada. A permutação define uma fila
imutável de candidatos. O primeiro candidato disponível recebe o primeiro
prêmio, o segundo recebe o próximo e assim sucessivamente.

O operador não pode pedir “outro número”, voltar, reiniciar ou trocar o modo de
aleatoriedade. Fechar e abrir o aplicativo produz exatamente a mesma fila.

## 8. Ausência e erro operacional

- **Ausência confirmada:** registra a chamada, exclui o participante do evento
  e entrega o mesmo prêmio ao próximo candidato da fila.
- **Erro operacional:** não gera novo candidato. A correção reapresenta o mesmo
  participante e o mesmo prêmio. Essa regra impede anular ganhadores
  desfavoráveis sob o rótulo de erro.
- **Problema na lista após o lacre:** cancela formalmente o evento inteiro. Não
  existe edição pontual da lista lacrada.

## 9. Persistência atômica

Cada revelação acontece numa transação SQLite `IMMEDIATE`:

1. confirmar estado e posição atual;
2. calcular ou ler o candidato determinístico;
3. gravar chamada e entrada do diário;
4. executar `COMMIT` durável;
5. somente depois mostrar o nome na tela.

Duplo clique recebe o mesmo resultado já confirmado. Queda de energia antes do
commit não revela ganhador; depois do commit, a recuperação mostra a chamada
existente.

## 10. Evidências por chamada

Cada chamada registra:

- versão do algoritmo;
- `event_uuid`, `list_hash` e `prizes_hash`;
- hash da semente, sem expor segredos antes da cerimônia;
- posição na permutação;
- quantidade inicial e situação do candidato;
- UUID e ticket selecionados;
- prêmio e ordem;
- operador, confirmação dos auditores e horário local;
- hash anterior e atual do diário.

## 11. Vetores de teste

A implementação só pode ser liberada após publicar vetores imutáveis contendo:

- pacote de entrada;
- compromissos e revelações dos auditores;
- resultado da Federal;
- `list_hash`, `prizes_hash`, `seed_hash` e permutação esperada;
- chamadas e raiz final esperadas.

Rust, CLI e verificador devem produzir byte a byte o mesmo resultado em Windows
e Linux. Mudança em qualquer byte exige uma nova versão do protocolo.

## 12. Verificação independente

O verificador reconstrói canonicalização, compromissos, HKDF, ChaCha20,
rejection sampling, Fisher-Yates e associação dos prêmios. Ele também valida a
cadeia de auditoria e produz um laudo com o primeiro ponto de divergência.

O processo é considerado íntegro somente se todas as etapas forem reproduzidas
e a raiz final coincidir.

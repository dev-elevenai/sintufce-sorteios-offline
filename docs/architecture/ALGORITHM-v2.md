# SINTUFCE Draw Protocol v2

## Garantia principal

O resultado depende exclusivamente de:

1. conjunto de participantes identificado por UUID;
2. cinco números oficiais da Loteria Federal, na ordem do primeiro ao quinto;
3. quantidade de participantes.

A ordem das linhas no CSV, nomes, SIAPEs e números visuais dos tickets não
alteram o resultado. Para a mesma lista e a mesma chave da Federal, a
permutação e os ganhadores são sempre idênticos.

## Lista canônica

Participantes são ordenados pelos 16 bytes do UUID v4, em ordem lexicográfica.
O hash da lista usa SHA-256, domínio `SINTUFCE/ELIGIBLES/V1`, quantidade e
campos com tamanho prefixado. Assim, reordenar a planilha não altera o hash nem
a associação entre posição e participante.

Prêmios são ordenados pelo campo `ordem` e lacrados por hash próprio.

## Chave da Loteria Federal

Dos cinco números são extraídos os últimos três dígitos, preservando zeros à
esquerda e a ordem oficial:

```text
1º: 087637 -> 637
2º: 075621 -> 621
3º: 078748 -> 748
4º: 055165 -> 165
5º: 075592 -> 592

chave = 637621748165592
```

Se a chave for novamente `637621748165592`, a lista canônica receberá a mesma
permutação. Para uma chave simples ilustrativa `123`, o princípio é o mesmo:
mesma chave e mesma lista produzem o mesmo resultado.

## Derivação e embaralhamento

```text
seed = SHA-256("SINTUFCE/FEDERAL-SHUFFLE/V2\0" || chave)
nonce = first_12_bytes(SHA-256("SINTUFCE/NONCE/V2\0"))
```

O stream ChaCha20 segue RFC 8439. Inteiros `u64` little-endian alimentam
rejection sampling, eliminando viés modular. Fisher-Yates percorre a lista do
último índice ao primeiro e produz uma permutação completa.

Não são usados `Math.random`, ponto flutuante, relógio, ordem de importação,
UUID do evento ou segredos internos. Auditores conferem as evidências, mas não
influenciam a chave.

## Associação aos prêmios

A permutação é uma fila determinística. O primeiro UUID recebe o primeiro
prêmio, o segundo recebe o segundo prêmio e assim sucessivamente. A interface
revela um resultado por vez sem recalcular ou permitir nova tentativa.

Ausência consome o participante e entrega o mesmo prêmio ao próximo UUID da
fila. O histórico mantém a chamada ausente. Erro de lista após o lacre exige
cancelamento formal do evento; não existe edição silenciosa.

## Evidências

O relatório registra:

- versão `SINTUFCE-DRAW-V2`;
- cinco números oficiais e chave extraída;
- hash da lista e dos prêmios;
- hash da semente;
- permutação e chamadas;
- cadeia SHA-256 do diário.

O verificador independente recalcula tudo e rejeita lista reordenada com
conteúdo diferente, chave divergente, ganhador repetido, prêmio repetido ou
qualquer quebra na cadeia de auditoria.

## Vetor público

Para os números `87637, 75621, 78748, 55165, 75592`:

```text
chave: 637621748165592
seed_hash: 74a1716db0c7769e6f8fe9202218358e4de6f1712a4dd0d909bbe69a280ea9c7
permutação para 10 posições: 3,4,6,1,2,8,0,9,7,5
```

Esse vetor é testado em CI. Mudança em qualquer byte exige nova versão do
protocolo.

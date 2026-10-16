# Protocolo seguro de transferência v1

## Objetivo

Transportar um evento da plataforma web para o aplicativo isolado e devolver o
resultado à plataforma sem depender de rede durante o sorteio, sem exigir que o
computador seja conhecido antecipadamente e sem aceitar alteração silenciosa
dos dados.

O resultado válido é definido matematicamente pelos dados canônicos do evento,
pelos prêmios e pelos cinco números da Loteria Federal. A identidade temporária
do aplicativo protege a continuidade da sessão, mas não interfere na escolha
dos ganhadores.

## Propriedades obrigatórias

1. Alterar qualquer byte relevante invalida a assinatura ou a recomputação.
2. A ordem das linhas importadas não altera o resultado.
3. O mesmo conjunto de elegíveis, os mesmos prêmios e a mesma chave Federal
   produzem os mesmos ganhadores em qualquer instalação compatível.
4. Um pacote pertence a um único evento e só pode originar um resultado final.
5. Reimportar o mesmo resultado é idempotente; apresentar outro resultado para
   o mesmo evento é conflito e deve ser rejeitado.
6. A web nunca executa arquivos recebidos e só extrai nomes expressamente
   permitidos.
7. O aplicativo não precisa de internet e não depende de relógio confiável para
   determinar ganhadores.

## Modelo de confiança sem computador pré-cadastrado

A plataforma web possui uma chave Ed25519 de emissão. A chave privada permanece
no servidor; a chave pública correspondente acompanha o aplicativo e pode ser
rotacionada por versão.

Ao importar um pacote válido, o aplicativo cria um par Ed25519 exclusivo para o
evento. A chave privada fica protegida pelo cofre de credenciais do Windows e a
chave pública entra no diário de auditoria. Todas as ações posteriores e o
resultado final são assinados por essa identidade temporária.

Essa identidade prova que a mesma sessão que recebeu o pacote realizou e
exportou o evento. Ela não pretende identificar fisicamente o computador. A
validade material do resultado vem da assinatura da web no pacote original e da
recomputação determinística feita pela web ao receber o resultado.

## Web para aplicativo: `.sintufce`

O pacote é um ZIP limitado aos seguintes arquivos:

- `manifest.json`
- `elegiveis.csv`
- `premios.csv`
- `signature.ed25519`
- `key-id.txt`
- `origem.pdf`, opcional

O manifesto canônico registra:

- versão do formato e do algoritmo;
- UUID e nome do evento;
- instante de fechamento informativo;
- nonce aleatório de exportação com 256 bits;
- contagens e SHA-256 dos arquivos;
- identificador da chave de emissão;
- estado `FECHADO_PARA_SORTEIO`.

A assinatura cobre o domínio `SINTUFCE/PACKAGE/V2`, o manifesto canônico e os
hashes dos arquivos. O aplicativo possui as chaves públicas aceitas e rejeita
uma chave indicada pelo pacote que não esteja nessa lista.

### Validação antes da gravação

O aplicativo deve:

1. limitar o tamanho total, o tamanho descompactado e a quantidade de entradas;
2. rejeitar nomes absolutos, `..`, links, duplicatas, diretórios e arquivos não
   permitidos;
3. conferir assinatura antes de interpretar os CSVs;
4. conferir hashes, esquema, UUIDs, contagens e codificação UTF-8;
5. rejeitar participantes que não sejam filiados e identificadores repetidos;
6. rejeitar prêmios com ordem repetida ou inválida;
7. impedir nova importação do mesmo evento, nonce ou hash do pacote;
8. gravar pacote, identidade temporária e primeiro registro de auditoria em uma
   única transação.

Falhar em qualquer item rejeita o pacote inteiro e não deixa evento parcial.

## Execução e resultado determinístico

Antes do sorteio, participantes são ordenados pelo UUID em bytes e prêmios por
ordem, com critérios de desempate definidos pelo protocolo. A chave Federal é a
concatenação, na sequência oficial, dos três últimos dígitos de cada um dos
cinco números.

O protocolo `SINTUFCE/FEDERAL-SHUFFLE/V2` deriva a semente com SHA-256 e executa
Fisher-Yates com ChaCha20 e rejection sampling. Dados de instalação, horário,
ordem da planilha, assinatura, nonce e UUID do evento não entram na seleção.

O verificador deve recomputar a permutação completa e comparar cada associação
entre prêmio e ganhador. Conferir apenas hashes ou apenas o primeiro ganhador é
insuficiente.

## Aplicativo para web: `.sintufce-result`

O pacote final contém somente:

- `result-manifest.json`
- `resultado.json`
- `auditoria.jsonl`
- `session-public-key.ed25519`
- `signature.ed25519`
- `ata.pdf`, opcional

O manifesto registra o UUID do evento, nonce e hash do pacote original, hashes
canônicos das listas, números Federal, chave Federal, hash da semente, versão do
algoritmo, raiz final da auditoria, chave pública temporária e hashes de todos
os arquivos. A assinatura da sessão cobre o domínio
`SINTUFCE/RESULT/V1`, o manifesto canônico e os hashes.

## Importação do resultado na web

A API processa o arquivo em memória limitada ou área temporária sem permissão de
execução. Dentro de uma transação, ela:

1. localiza o evento fechado e o pacote original pelo UUID, nonce e hash;
2. valida estrutura, limites e assinatura da sessão;
3. valida a cadeia de auditoria desde a importação original;
4. confere que participantes e prêmios são exatamente os exportados;
5. recalcula chave Federal, semente, permutação e todos os ganhadores;
6. rejeita repetições, ausências não justificadas e prêmio desconhecido;
7. grava resultado, arquivo-fonte, hash final e responsável pela importação;
8. marca o evento como `FINALIZADO` e imutável.

Se o mesmo hash final já estiver armazenado, a API devolve sucesso idempotente.
Se o evento já possuir outro hash final, devolve conflito e preserva os dados.

## Rotação, recuperação e cadeia de custódia

A web mantém um chaveiro público com identificador, início, fim e estado de
revogação. A revogação impede novas exportações; pacotes históricos continuam
verificáveis conforme a política registrada no instante da emissão.

A chave temporária do evento pode ser copiada somente dentro de um backup
criptografado criado pelo aplicativo. Perder a chave antes da exportação exige
cancelar o evento na web e gerar um novo pacote; não existe recuperação oculta.

Na entrega física, a interface mostra um código curto derivado do hash do pacote
e, no retorno, um código derivado do hash final. Esses códigos servem à
conferência humana e nunca substituem as assinaturas.

## Limites iniciais

- máximo de 25 MiB por pacote;
- máximo de 10 MiB por entrada;
- máximo de 8 entradas;
- máximo de 100 mil elegíveis e 10 mil prêmios;
- somente UTF-8, sem fórmulas, macros ou arquivos executáveis;
- formatos desconhecidos são recusados, sem tentativa de compatibilidade.

## Testes de aceitação

1. Vetor público fixa chave, semente, permutação e ganhadores esperados.
2. Cem reordenações da mesma lista produzem resultado byte a byte idêntico.
3. Implementações web, núcleo Rust, CLI e verificador produzem o mesmo vetor.
4. Um byte alterado em cada arquivo causa rejeição.
5. Manifesto refeito por terceiro continua inválido sem a chave da web.
6. Resultado assinado por outra sessão é rejeitado.
7. Replay do mesmo resultado é idempotente; resultado conflitante é rejeitado.
8. ZIP traversal, duplicata, bomba de compressão e arquivo extra são rejeitados.
9. Falha de energia durante importação ou finalização não deixa estado parcial.
10. A web só finaliza o evento após recomputar integralmente o sorteio.


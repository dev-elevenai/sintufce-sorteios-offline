# Pacote SINTUFCE v1

O arquivo `.sintufce` é um ZIP contendo exatamente `manifest.json`,
`elegiveis.csv` e `premios.csv`, além dos opcionais `origem.pdf` e
`assinatura.ed25519`.

`manifest.json` registra versão, UUID e nome do evento, fechamento, contagens e
SHA-256 dos dois CSVs. A importação é atômica: qualquer divergência rejeita o
pacote inteiro.

Elegíveis usam as colunas `ticket,uuid,nome,siape,situacao_vinculo`. Somente
`situacao_vinculo=FILIADO` é aceito; desfiliados são rejeitados antes do lacre.
Prêmios usam `ordem,premio`. CPF não pertence ao pacote.

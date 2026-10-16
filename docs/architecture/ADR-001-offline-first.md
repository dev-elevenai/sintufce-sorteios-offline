# ADR-001 — Runtime integralmente offline

## Decisão

O motor funciona sem rede, servidor externo ou processo web local. A aplicação
desktop chama uma biblioteca Rust dentro do próprio processo e persiste em
SQLite local. Dados entram e saem apenas por arquivos escolhidos pelo operador.

## Consequências

- Resultados externos, como Loteria Federal, exigem entrada manual conferida.
- Não há sincronização, recuperação em nuvem ou atualização automática.
- O instalador inclui todas as dependências e assets.
- O CI pode usar internet para compilar; o executável distribuído não usa rede.

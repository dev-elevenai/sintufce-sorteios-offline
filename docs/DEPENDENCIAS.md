# Dependências e operação offline

## Computador do sorteio

O operador recebe um instalador Windows x64. Não precisa instalar Node.js,
Rust, PostgreSQL, Docker ou servidor local.

Requisitos:

- Windows 10 ou 11 x64;
- Microsoft Edge WebView2 Runtime;
- conta operacional sem privilégios administrativos;
- BitLocker e Secure Boot recomendados;
- espaço local para aplicativo, banco e relatórios;
- impressora opcional para atas.

O instalador final verificará o WebView2 e oferecerá o pacote offline quando ele
não estiver disponível. Banco SQLite e assets pertencem ao próprio aplicativo.

## Ambiente de desenvolvimento

- Rust stable com `rustfmt` e `clippy`;
- Node.js 22 e npm;
- Visual Studio Build Tools 2022;
- Windows SDK;
- Tauri 2;
- NSIS e WiX para instaladores.

O CI compila o executável em runner Windows. O runtime distribuído não consulta
GitHub, registro de pacotes ou qualquer serviço externo.

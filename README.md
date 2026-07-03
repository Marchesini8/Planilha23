# Planilha Financeira Pessoal

Mini app financeiro em HTML, CSS e JavaScript puro para controlar salário, gastos, metas, gráficos e backups no navegador.

Os dados atuais ficam salvos no `LocalStorage`, então fechar e abrir o navegador não apaga salário, gastos ou metas. A limpeza só acontece se você usar o botão de limpar dados e confirmar.

## Rodar localmente

Abra `index.html` diretamente no navegador.

Para testar como app web:

```bash
npm start
```

## Deploy no Railway

O projeto já inclui `package.json` e `server.js`. No Railway, conecte o repositório e use o comando padrão:

```bash
npm start
```

## Base PostgreSQL

O arquivo `database/schema.sql` cria a base inicial para evoluir o projeto para login:

- `users`
- `user_profiles`
- `financial_goals`
- `expenses`

No Railway, crie um serviço PostgreSQL, copie a variável `DATABASE_URL` para o app e execute o schema no banco. A integração com login/API pode ser feita em uma próxima etapa usando essas tabelas.

# ProShape Webhook — Cloudflare + Hyperdrive

Pacote preparado para manter o webhook atual do Mercado Pago e adicionar acesso ao PostgreSQL via Hyperdrive.

## O que foi alterado

- Mantida a lógica existente de produção e teste do Mercado Pago.
- Mantida a validação de assinatura HMAC.
- Mantidos os planos ProShape e tratamento do simulador.
- Adicionado `pg` (node-postgres).
- Adicionado binding `PROSHAPE_DB` no `wrangler.jsonc`.
- Adicionado endpoint seguro de diagnóstico `/db-health`.
- `/db-health` executa apenas `SELECT 1`; não lê nem altera dados de alunos.

## Teste esperado

Após o deploy, abrir:

`https://proshape-webhook.willkctt2.workers.dev/db-health`

Resposta esperada:

```json
{
  "ok": true,
  "service": "ProShape Database",
  "database": "connected",
  "hyperdrive": "PROSHAPE_DB"
}
```

## Importante

Os secrets do Mercado Pago permanecem configurados no painel da Cloudflare e não estão neste pacote.

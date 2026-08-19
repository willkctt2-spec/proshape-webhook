# ProShape Webhook — Cloudflare + Hyperdrive

Webhook oficial da ProShape para integração com o Mercado Pago, executado em Cloudflare Workers e conectado ao PostgreSQL atual por meio do Cloudflare Hyperdrive.

---

## Objetivo

Este projeto mantém a lógica existente do webhook do Mercado Pago e adiciona acesso ao banco PostgreSQL da ProShape sem migrar os dados atuais.

A arquitetura utilizada é:

```text
Mercado Pago
    ↓
Cloudflare Worker
    ↓
Cloudflare Hyperdrive
    ↓
PostgreSQL ProShape

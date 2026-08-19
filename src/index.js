import { Client } from "pg";

const encoder = new TextEncoder();


/*
 * ============================================================
 * PROSHAPE - MERCADO PAGO WEBHOOK
 * ============================================================
 *
 * /
 *      PRODUÇÃO
 *
 * /test
 *      TESTE
 *
 * ============================================================
 */


/*
 * ============================================================
 * PLANOS PROSHAPE
 * ============================================================
 *
 * IMPORTANTE:
 *
 * Produção = Conta oficial ProShape
 * Teste    = Conta vendedora de teste
 *
 * ============================================================
 */

const PROSHAPE_PLANS = {

  production: {

    d27387971674447895c70022508e5bb4: {
      key: "mensal",
      name: "ProShape Mensal",
      amount: 29.90,
      frequency: 1,
      frequencyType: "months"
    },

    "19b9f24a0abf459386c5a706b18d0e9a": {
      key: "trimestral",
      name: "ProShape Trimestral",
      amount: 84.90,
      frequency: 3,
      frequencyType: "months"
    },

    "153a4b17b65e445283b94a37fc4a5b0e": {
      key: "anual",
      name: "ProShape Anual",
      amount: 299.90,
      frequency: 12,
      frequencyType: "months"
    }
  },


  test: {

    "0b787e8eb57c4fcdb615d2c7fa18a510": {
      key: "mensal",
      name: "ProShape Mensal",
      amount: 29.90,
      frequency: 1,
      frequencyType: "months"
    },

    "69b9bf7b9b334157bd285392171316ea": {
      key: "trimestral",
      name: "ProShape Trimestral",
      amount: 84.90,
      frequency: 3,
      frequencyType: "months"
    },

    "7fd0f1dcfdbb461e96c8f74cb66c81d4": {
      key: "anual",
      name: "ProShape Anual",
      amount: 299.90,
      frequency: 12,
      frequencyType: "months"
    }
  }
};

const PROSHAPE_PLAN_ACCESS_DAYS = {
  mensal: 30,
  trimestral: 90,
  anual: 365
};


/*
 * ============================================================
 * IDENTIFICAR PLANO
 * ============================================================
 */

function identifyProShapePlan(
  environmentName,
  planId
) {
  if (!planId) {
    return null;
  }

  const environmentPlans =
    PROSHAPE_PLANS[
      environmentName
    ];

  if (!environmentPlans) {
    return null;
  }

  const plan =
    environmentPlans[
      String(planId)
    ];

  if (!plan) {
    return null;
  }

  return {
    id:
      String(planId),

    key:
      plan.key,

    name:
      plan.name,

    amount:
      plan.amount,

    frequency:
      plan.frequency,

    frequencyType:
      plan.frequencyType
  };
}


/*
 * ============================================================
 * RESPOSTA JSON
 * ============================================================
 */

function jsonResponse(
  data,
  status = 200
) {
  return new Response(
    JSON.stringify(
      data,
      null,
      2
    ),
    {
      status,

      headers: {
        "content-type":
          "application/json; charset=UTF-8"
      }
    }
  );
}


/*
 * ============================================================
 * PARSE X-SIGNATURE
 * ============================================================
 */

function parseSignatureHeader(
  header
) {
  const result = {
    ts: "",
    v1: ""
  };

  if (!header) {
    return result;
  }

  for (
    const part of
    String(header).split(",")
  ) {
    const [
      key,
      ...valueParts
    ] =
      part
        .trim()
        .split("=");

    const value =
      valueParts.join("=");

    if (key === "ts") {
      result.ts =
        value;
    }

    if (key === "v1") {
      result.v1 =
        value;
    }
  }

  return result;
}


/*
 * ============================================================
 * HEX -> BYTES
 * ============================================================
 */

function hexToBytes(
  hex
) {
  if (!hex) {
    return null;
  }

  const normalized =
    String(hex)
      .trim()
      .toLowerCase();

  if (
    normalized.length === 0 ||
    normalized.length % 2 !== 0 ||
    !/^[0-9a-f]+$/.test(
      normalized
    )
  ) {
    return null;
  }

  const bytes =
    new Uint8Array(
      normalized.length / 2
    );

  for (
    let i = 0;
    i < normalized.length;
    i += 2
  ) {
    bytes[i / 2] =
      Number.parseInt(
        normalized.slice(
          i,
          i + 2
        ),
        16
      );
  }

  return bytes;
}


/*
 * ============================================================
 * VALIDAR ASSINATURA MERCADO PAGO
 * ============================================================
 */

async function validateMercadoPagoSignature(
  request,
  secret,
  environmentName
) {
  if (!secret) {
    throw new Error(
      `Webhook Secret não configurado para ${environmentName}`
    );
  }

  const url =
    new URL(
      request.url
    );

  const xSignature =
    request.headers.get(
      "x-signature"
    );

  const xRequestId =
    request.headers.get(
      "x-request-id"
    );

  const {
    ts,
    v1
  } =
    parseSignatureHeader(
      xSignature
    );

  if (
    !ts ||
    !v1
  ) {
    console.warn(
      `Webhook ${environmentName}: x-signature ausente ou incompleto`
    );

    return false;
  }


  /*
   * DATA ID
   */

  let dataId =
    url.searchParams.get(
      "data.id"
    );

  if (dataId) {
    dataId =
      String(dataId)
        .toLowerCase();
  }


  /*
   * MANIFESTO
   */

  let manifest = "";

  if (dataId) {
    manifest +=
      `id:${dataId};`;
  }

  if (xRequestId) {
    manifest +=
      `request-id:${xRequestId};`;
  }

  manifest +=
    `ts:${ts};`;


  /*
   * HMAC SHA-256
   */

  const key =
    await crypto.subtle.importKey(
      "raw",
      encoder.encode(
        secret
      ),
      {
        name:
          "HMAC",

        hash:
          "SHA-256"
      },
      false,
      [
        "verify"
      ]
    );


  const signatureBytes =
    hexToBytes(
      v1
    );

  if (!signatureBytes) {
    console.warn(
      `Webhook ${environmentName}: assinatura inválida`
    );

    return false;
  }


  const valid =
    await crypto.subtle.verify(
      "HMAC",
      key,
      signatureBytes,
      encoder.encode(
        manifest
      )
    );


  /*
   * LOG SEGURO
   */

  console.log(
    "Validação Mercado Pago:",
    JSON.stringify({
      environment:
        environmentName,

      dataId:
        dataId ?? null,

      requestId:
        xRequestId ?? null,

      signatureValid:
        valid
    })
  );


  return valid;
}


/*
 * ============================================================
 * AMBIENTE
 * ============================================================
 */

function getEnvironment(
  url,
  env
) {
  const pathname =
    url.pathname
      .replace(
        /\/+$/,
        ""
      ) ||
    "/";


  /*
   * TESTE
   */

  if (
    pathname ===
    "/test"
  ) {
    return {
      name:
        "test",

      accessToken:
        env.MERCADO_PAGO_TEST_ACCESS_TOKEN,

      webhookSecret:
        env.MERCADO_PAGO_TEST_WEBHOOK_SECRET
    };
  }


  /*
   * PRODUÇÃO
   */

  return {
    name:
      "production",

    accessToken:
      env.MERCADO_PAGO_ACCESS_TOKEN,

    webhookSecret:
      env.MERCADO_PAGO_WEBHOOK_SECRET
  };
}


/*
 * ============================================================
 * API MERCADO PAGO
 * ============================================================
 */

async function mercadoPagoGet(
  path,
  accessToken
) {
  if (!accessToken) {
    throw new Error(
      "Access Token Mercado Pago não configurado"
    );
  }

  const response =
    await fetch(
      `https://api.mercadopago.com${path}`,
      {
        method:
          "GET",

        headers: {
          Authorization:
            `Bearer ${accessToken}`,

          Accept:
            "application/json"
        }
      }
    );


  const text =
    await response.text();


  let data =
    null;

  try {

    data =
      text
        ? JSON.parse(
            text
          )
        : null;

  } catch {

    data = {
      raw:
        text
    };
  }


  if (
    !response.ok
  ) {
    throw new Error(
      `Mercado Pago API ${response.status}: ${text}`
    );
  }


  return data;
}


/*
 * ============================================================
 * CONSULTAR PAGAMENTO
 * ============================================================
 */

async function getPayment(
  id,
  accessToken
) {
  return mercadoPagoGet(
    `/v1/payments/${encodeURIComponent(id)}`,
    accessToken
  );
}


/*
 * ============================================================
 * CONSULTAR PAGAMENTO AUTORIZADO DA ASSINATURA
 * ============================================================
 */

async function getAuthorizedPayment(
  id,
  accessToken
) {
  return mercadoPagoGet(
    `/authorized_payments/${encodeURIComponent(id)}`,
    accessToken
  );
}


/*
 * ============================================================
 * CONSULTAR ASSINATURA
 * ============================================================
 */

async function getSubscription(
  id,
  accessToken
) {
  return mercadoPagoGet(
    `/preapproval/${encodeURIComponent(id)}`,
    accessToken
  );
}


/*
 * ============================================================
 * RESUMO PAGAMENTO
 * ============================================================
 */

function paymentSummary(
  payment
) {
  return {

    id:
      payment?.id ??
      null,

    status:
      payment?.status ??
      null,

    statusDetail:
      payment?.status_detail ??
      null,

    amount:
      payment?.transaction_amount ??
      null,

    currency:
      payment?.currency_id ??
      null,

    description:
      payment?.description ??
      null,

    externalReference:
      payment?.external_reference ??
      null,

    payer: {

      id:
        payment?.payer?.id ??
        null,

      email:
        payment?.payer?.email ??
        null,

      firstName:
        payment?.payer?.first_name ??
        null,

      lastName:
        payment?.payer?.last_name ??
        null
    },

    dateApproved:
      payment?.date_approved ??
      null,

    operationType:
      payment?.operation_type ??
      null,

    paymentMethod:
      payment?.payment_method_id ??
      null
  };
}


/*
 * ============================================================
 * RESUMO PAGAMENTO AUTORIZADO
 * ============================================================
 */

function authorizedPaymentSummary(
  authorizedPayment
) {
  return {
    id:
      authorizedPayment?.id ??
      null,

    status:
      authorizedPayment?.status ??
      null,

    summarized:
      authorizedPayment?.summarized ??
      null,

    preapprovalId:
      authorizedPayment?.preapproval_id ??
      null,

    reason:
      authorizedPayment?.reason ??
      null,

    externalReference:
      authorizedPayment?.external_reference ??
      null,

    currency:
      authorizedPayment?.currency_id ??
      null,

    amount:
      authorizedPayment?.transaction_amount ??
      null,

    debitDate:
      authorizedPayment?.debit_date ??
      null,

    retryAttempt:
      authorizedPayment?.retry_attempt ??
      null,

    paymentId:
      authorizedPayment?.payment?.id ??
      null,

    paymentStatus:
      authorizedPayment?.payment?.status ??
      null,

    paymentStatusDetail:
      authorizedPayment?.payment?.status_detail ??
      null
  };
}


/*
 * ============================================================
 * RESUMO ASSINATURA
 * ============================================================
 */

function subscriptionSummary(
  subscription
) {
  return {

    id:
      subscription?.id ??
      null,

    status:
      subscription?.status ??
      null,

    reason:
      subscription?.reason ??
      null,

    externalReference:
      subscription
        ?.external_reference ??
      null,

    planId:
      subscription
        ?.preapproval_plan_id ??
      null,

    payerId:
      subscription
        ?.payer_id ??
      null,

    payerEmail:
      subscription
        ?.payer_email ??
      null,

    dateCreated:
      subscription
        ?.date_created ??
      null,

    lastModified:
      subscription
        ?.last_modified ??
      null,

    nextPaymentDate:
      subscription
        ?.next_payment_date ??
      null,

    autoRecurring:
      subscription
        ?.auto_recurring
        ? {

            frequency:
              subscription
                .auto_recurring
                .frequency ??
              null,

            frequencyType:
              subscription
                .auto_recurring
                .frequency_type ??
              null,

            transactionAmount:
              subscription
                .auto_recurring
                .transaction_amount ??
              null,

            currencyId:
              subscription
                .auto_recurring
                .currency_id ??
              null
          }
        :
          null
  };
}


/*
 * ============================================================
 * VALIDAR CONFIGURAÇÃO DO PLANO
 * ============================================================
 */

function validatePlanConfiguration(
  plan,
  subscriptionSummaryData
) {
  if (
    !plan ||
    !subscriptionSummaryData
  ) {
    return {
      valid:
        false,

      reason:
        "Plano não identificado"
    };
  }


  const recurring =
    subscriptionSummaryData
      .autoRecurring;


  if (!recurring) {
    return {
      valid:
        false,

      reason:
        "Informações de recorrência ausentes"
    };
  }


  const amountMatches =
    Number(
      recurring.transactionAmount
    ) ===
    Number(
      plan.amount
    );


  const frequencyMatches =
    Number(
      recurring.frequency
    ) ===
    Number(
      plan.frequency
    );


  const frequencyTypeMatches =
    recurring.frequencyType ===
    plan.frequencyType;


  return {

    valid:
      amountMatches &&
      frequencyMatches &&
      frequencyTypeMatches,

    amountMatches,

    frequencyMatches,

    frequencyTypeMatches
  };
}



/*
 * ============================================================
 * AUTOMAÇÃO DE ACESSO PROSHAPE
 * ============================================================
 *
 * Fonte de verdade para liberar/renovar acesso:
 * subscription_authorized_payment com pagamento aprovado.
 *
 * Produção:
 *   atualiza o aluno.
 *
 * Teste:
 *   DRY-RUN. Não altera acesso de aluno real.
 *
 * Idempotência:
 *   tabela proshape_payment_events evita renovar duas vezes
 *   quando o Mercado Pago reenviar a mesma notificação.
 * ============================================================
 */

function normalizeEmail(
  value
) {
  return String(
    value ?? ""
  )
    .trim()
    .toLowerCase();
}


function brazilToday() {
  const parts =
    new Intl.DateTimeFormat(
      "en-CA",
      {
        timeZone:
          "America/Sao_Paulo",

        year:
          "numeric",

        month:
          "2-digit",

        day:
          "2-digit"
      }
    )
      .formatToParts(
        new Date()
      );

  const values =
    Object.fromEntries(
      parts.map(
        (part) => [
          part.type,
          part.value
        ]
      )
    );

  return (
    `${values.year}-${values.month}-${values.day}`
  );
}


function dateOnlyFromIso(
  value
) {
  const text =
    String(
      value ?? ""
    );

  const match =
    text.match(
      /^(\d{4}-\d{2}-\d{2})/
    );

  return (
    match?.[1] ??
    null
  );
}


function addDaysToDateOnly(
  dateString,
  days
) {
  const safeDays =
    Math.max(
      1,
      Math.min(
        3660,
        Math.floor(
          Number(days) ||
          0
        )
      )
    );

  const date =
    new Date(
      `${dateString}T12:00:00.000Z`
    );

  date.setUTCDate(
    date.getUTCDate() +
    safeDays
  );

  return date
    .toISOString()
    .slice(
      0,
      10
    );
}


function laterDateOnly(
  a,
  b
) {
  if (!a) {
    return b ?? null;
  }

  if (!b) {
    return a ?? null;
  }

  return (
    String(a) >=
    String(b)
  )
    ? String(a)
    : String(b);
}


function planAccessDays(
  plan
) {
  return (
    PROSHAPE_PLAN_ACCESS_DAYS[
      plan?.key
    ] ??
    0
  );
}


async function createDatabaseClient(
  env
) {
  if (
    !env.PROSHAPE_DB
      ?.connectionString
  ) {
    throw new Error(
      "Binding PROSHAPE_DB não configurada"
    );
  }

  const client =
    new Client({
      connectionString:
        env.PROSHAPE_DB
          .connectionString
    });

  await client.connect();

  return client;
}


async function ensurePaymentEventsTable(
  client
) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS proshape_payment_events (
      environment TEXT NOT NULL,
      event_key TEXT NOT NULL,
      topic TEXT NOT NULL,
      authorized_payment_id TEXT,
      payment_id TEXT,
      subscription_id TEXT,
      payer_email TEXT,
      plan_key TEXT,
      plan_name TEXT,
      amount NUMERIC(10, 2),
      currency TEXT,
      payment_status TEXT,
      student_id TEXT,
      processed BOOLEAN NOT NULL DEFAULT FALSE,
      result TEXT NOT NULL DEFAULT 'received',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (environment, event_key)
    )
  `);

  await client.query(`
    CREATE INDEX IF NOT EXISTS
      proshape_payment_events_student_idx
    ON proshape_payment_events (student_id)
  `);

  await client.query(`
    CREATE INDEX IF NOT EXISTS
      proshape_payment_events_payment_idx
    ON proshape_payment_events (payment_id)
  `);
}


async function processProShapeSubscriptionPayment({
  env,
  environmentName,
  topic,
  authorizedPaymentSummaryData,
  paymentSummaryData,
  subscriptionSummaryData,
  plan,
  planValidation
}) {
  const authorizedPaymentId =
    authorizedPaymentSummaryData?.id
      ? String(
          authorizedPaymentSummaryData.id
        )
      : "";

  const paymentId =
    paymentSummaryData?.id
      ? String(
          paymentSummaryData.id
        )
      :
      authorizedPaymentSummaryData
        ?.paymentId
        ? String(
            authorizedPaymentSummaryData
              .paymentId
          )
        : "";

  const subscriptionId =
    subscriptionSummaryData?.id
      ? String(
          subscriptionSummaryData.id
        )
      :
      authorizedPaymentSummaryData
        ?.preapprovalId
        ? String(
            authorizedPaymentSummaryData
              .preapprovalId
          )
        : "";

  const eventKey =
    paymentId
      ? `payment:${paymentId}`
      :
      authorizedPaymentId
        ? `authorized:${authorizedPaymentId}`
        : "";

  if (!eventKey) {
    return {
      ok:
        false,

      processed:
        false,

      reason:
        "Evento sem identificador idempotente"
    };
  }


  const paymentStatus =
    paymentSummaryData?.status ??
    authorizedPaymentSummaryData
      ?.paymentStatus ??
    null;

  const payerEmail =
    normalizeEmail(
      subscriptionSummaryData
        ?.payerEmail ??
      paymentSummaryData
        ?.payer?.email ??
      ""
    );

  const amount =
    Number(
      paymentSummaryData?.amount ??
      authorizedPaymentSummaryData
        ?.amount ??
      0
    );

  const currency =
    paymentSummaryData?.currency ??
    authorizedPaymentSummaryData
      ?.currency ??
    null;


  /*
   * Segurança:
   * nunca libera acesso sem pagamento aprovado.
   */

  if (
    paymentStatus !==
    "approved"
  ) {
    return {
      ok:
        true,

      processed:
        false,

      reason:
        "Pagamento ainda não aprovado",

      paymentStatus
    };
  }


  /*
   * Segurança:
   * nunca libera acesso de plano desconhecido/divergente.
   */

  if (
    !plan ||
    !planValidation?.valid
  ) {
    return {
      ok:
        true,

      processed:
        false,

      reason:
        "Plano não identificado ou configuração divergente"
    };
  }


  /*
   * Segurança:
   * moeda deve ser BRL para os planos atuais.
   */

  if (
    currency &&
    String(currency) !==
    "BRL"
  ) {
    return {
      ok:
        true,

      processed:
        false,

      reason:
        "Moeda do pagamento inválida",

      currency
    };
  }


  if (!payerEmail) {
    return {
      ok:
        true,

      processed:
        false,

      reason:
        "Pagamento sem e-mail do comprador"
    };
  }


  const client =
    await createDatabaseClient(
      env
    );

  try {
    await ensurePaymentEventsTable(
      client
    );

    await client.query(
      "BEGIN"
    );

    try {
      /*
       * Registrar ou recuperar evento.
       */

      await client.query(
        `
          INSERT INTO proshape_payment_events (
            environment,
            event_key,
            topic,
            authorized_payment_id,
            payment_id,
            subscription_id,
            payer_email,
            plan_key,
            plan_name,
            amount,
            currency,
            payment_status,
            processed,
            result,
            updated_at
          )
          VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10, $11, $12,
            FALSE, 'received', NOW()
          )
          ON CONFLICT (environment, event_key)
          DO UPDATE SET
            topic = EXCLUDED.topic,
            authorized_payment_id = EXCLUDED.authorized_payment_id,
            payment_id = EXCLUDED.payment_id,
            subscription_id = EXCLUDED.subscription_id,
            payer_email = EXCLUDED.payer_email,
            plan_key = EXCLUDED.plan_key,
            plan_name = EXCLUDED.plan_name,
            amount = EXCLUDED.amount,
            currency = EXCLUDED.currency,
            payment_status = EXCLUDED.payment_status,
            updated_at = NOW()
        `,
        [
          environmentName,
          eventKey,
          topic,
          authorizedPaymentId ||
            null,
          paymentId ||
            null,
          subscriptionId ||
            null,
          payerEmail,
          plan.key,
          plan.name,
          amount ||
            null,
          currency,
          paymentStatus
        ]
      );


      const eventResult =
        await client.query(
          `
            SELECT
              processed,
              result,
              student_id
            FROM proshape_payment_events
            WHERE
              environment = $1
              AND event_key = $2
            FOR UPDATE
          `,
          [
            environmentName,
            eventKey
          ]
        );

      const existingEvent =
        eventResult.rows?.[0];


      /*
       * Idempotência:
       * já processado = não soma dias novamente.
       */

      if (
        existingEvent
          ?.processed ===
        true
      ) {
        await client.query(
          "COMMIT"
        );

        return {
          ok:
            true,

          processed:
            true,

          duplicate:
            true,

          result:
            existingEvent.result,

          studentId:
            existingEvent.student_id ??
            null,

          paymentId:
            paymentId ||
            null,

          plan:
            plan.key
        };
      }


      /*
       * Ambiente de teste:
       * valida tudo, mas NÃO altera alunos reais.
       */

      if (
        environmentName !==
        "production"
      ) {
        await client.query(
          `
            UPDATE proshape_payment_events
            SET
              processed = TRUE,
              result = 'dry_run_test',
              updated_at = NOW()
            WHERE
              environment = $1
              AND event_key = $2
          `,
          [
            environmentName,
            eventKey
          ]
        );

        await client.query(
          "COMMIT"
        );

        return {
          ok:
            true,

          processed:
            true,

          duplicate:
            false,

          dryRun:
            true,

          result:
            "dry_run_test",

          payerEmail,

          paymentId:
            paymentId ||
            null,

          plan:
            plan.key
        };
      }


      /*
       * Localizar aluno por e-mail.
       *
       * LIMIT 2:
       * se houver e-mail duplicado, não atualiza ninguém.
       */

      const studentsResult =
        await client.query(
          `
            SELECT
              id,
              name,
              code,
              email,
              paid_at,
              expires_at,
              blocked
            FROM students
            WHERE
              LOWER(TRIM(email)) = $1
            ORDER BY created_at ASC
            LIMIT 2
            FOR UPDATE
          `,
          [
            payerEmail
          ]
        );


      if (
        studentsResult.rows.length ===
        0
      ) {
        await client.query(
          `
            UPDATE proshape_payment_events
            SET
              processed = FALSE,
              result = 'student_not_found',
              updated_at = NOW()
            WHERE
              environment = $1
              AND event_key = $2
          `,
          [
            environmentName,
            eventKey
          ]
        );

        await client.query(
          "COMMIT"
        );

        return {
          ok:
            true,

          processed:
            false,

          result:
            "student_not_found",

          payerEmail,

          paymentId:
            paymentId ||
            null,

          plan:
            plan.key
        };
      }


      if (
        studentsResult.rows.length >
        1
      ) {
        await client.query(
          `
            UPDATE proshape_payment_events
            SET
              processed = FALSE,
              result = 'duplicate_student_email',
              updated_at = NOW()
            WHERE
              environment = $1
              AND event_key = $2
          `,
          [
            environmentName,
            eventKey
          ]
        );

        await client.query(
          "COMMIT"
        );

        return {
          ok:
            true,

          processed:
            false,

          result:
            "duplicate_student_email",

          payerEmail,

          paymentId:
            paymentId ||
            null,

          plan:
            plan.key
        };
      }


      const student =
        studentsResult.rows[0];

      const today =
        brazilToday();

      const currentExpiry =
        dateOnlyFromIso(
          student.expires_at
        ) ??
        (
          student.expires_at
            ? String(
                student.expires_at
              )
            : null
        );

      const nextPaymentDate =
        dateOnlyFromIso(
          subscriptionSummaryData
            ?.nextPaymentDate
        );

      /*
       * Preferência:
       * usar a próxima cobrança real do Mercado Pago.
       *
       * Fallback:
       * 30/90/365 dias conforme plano.
       */

      let newExpiry =
        null;

      if (
        nextPaymentDate &&
        nextPaymentDate >=
          today
      ) {
        newExpiry =
          laterDateOnly(
            currentExpiry,
            nextPaymentDate
          );
      } else {
        const baseDate =
          currentExpiry &&
          currentExpiry >=
            today
            ? currentExpiry
            : today;

        newExpiry =
          addDaysToDateOnly(
            baseDate,
            planAccessDays(
              plan
            )
          );
      }


      const updatedResult =
        await client.query(
          `
            UPDATE students
            SET
              paid_at = $1,
              expires_at = $2,
              blocked = FALSE,
              updated_at = NOW()
            WHERE
              id = $3
            RETURNING
              id,
              name,
              code,
              email,
              paid_at,
              expires_at,
              blocked
          `,
          [
            today,
            newExpiry,
            student.id
          ]
        );

      const updatedStudent =
        updatedResult.rows[0];


      await client.query(
        `
          UPDATE proshape_payment_events
          SET
            student_id = $1,
            processed = TRUE,
            result = 'access_renewed',
            updated_at = NOW()
          WHERE
            environment = $2
            AND event_key = $3
        `,
        [
          student.id,
          environmentName,
          eventKey
        ]
      );


      await client.query(
        "COMMIT"
      );


      console.log(
        "ACESSO PROSHAPE RENOVADO:",
        JSON.stringify({
          studentId:
            updatedStudent.id,

          studentName:
            updatedStudent.name,

          payerEmail,

          plan:
            plan.key,

          paymentId:
            paymentId ||
            null,

          paidAt:
            updatedStudent.paid_at,

          expiresAt:
            updatedStudent.expires_at
        })
      );


      return {
        ok:
          true,

        processed:
          true,

        duplicate:
          false,

        result:
          "access_renewed",

        student: {
          id:
            updatedStudent.id,

          name:
            updatedStudent.name,

          code:
            updatedStudent.code,

          email:
            updatedStudent.email,

          paidAt:
            updatedStudent.paid_at,

          expiresAt:
            updatedStudent.expires_at,

          blocked:
            updatedStudent.blocked
        },

        payerEmail,

        paymentId:
          paymentId ||
          null,

        plan:
          plan.key
      };

    } catch (error) {
      await client.query(
        "ROLLBACK"
      );

      throw error;
    }

  } finally {
    try {
      await client.end();
    } catch {
      // Nada a fazer.
    }
  }
}


/*
 * ============================================================
 * BANCO PROSHAPE - HYPERDRIVE
 * ============================================================
 *
 * Binding configurada no Cloudflare:
 * env.PROSHAPE_DB.connectionString
 *
 * Este helper faz apenas SELECT 1.
 * Não lê nem altera dados de alunos.
 * ============================================================
 */

async function checkProShapeDatabase(env) {
  if (!env.PROSHAPE_DB?.connectionString) {
    throw new Error(
      "Binding PROSHAPE_DB não configurada"
    );
  }

  const client = new Client({
    connectionString:
      env.PROSHAPE_DB.connectionString
  });

  try {
    await client.connect();

    const result =
      await client.query(
        "SELECT 1 AS ok"
      );

    return (
      Number(
        result?.rows?.[0]?.ok
      ) === 1
    );
  } finally {
    try {
      await client.end();
    } catch {
      // Nada a fazer.
    }
  }
}

/*
 * ============================================================
 * WORKER
 * ============================================================
 */

export default {

  async fetch(
    request,
    env
  ) {

    const url =
      new URL(
        request.url
      );


    /*
     * ========================================================
     * DEFINIR AMBIENTE
     * ========================================================
     */

    const environment =
      getEnvironment(
        url,
        env
      );


    /*
     * ========================================================
     * GET
     * ========================================================
     */

    if (
      request.method ===
      "GET"
    ) {

      /*
       * ======================================================
       * HEALTH CHECK DO POSTGRES VIA HYPERDRIVE
       * ======================================================
       *
       * URL:
       * /db-health
       *
       * Faz somente SELECT 1.
       * ======================================================
       */

      if (
        url.pathname.replace(/\/+$/, "") ===
        "/db-health"
      ) {
        try {
          const connected =
            await checkProShapeDatabase(
              env
            );

          return jsonResponse({
            ok:
              connected,

            service:
              "ProShape Database",

            database:
              connected
                ? "connected"
                : "not-connected",

            hyperdrive:
              "PROSHAPE_DB"
          });
        } catch (error) {
          console.error(
            "Erro no health check do banco:",
            error instanceof Error
              ? error.message
              : String(error)
          );

          return jsonResponse(
            {
              ok:
                false,

              service:
                "ProShape Database",

              database:
                "error",

              error:
                "Database connection failed"
            },
            500
          );
        }
      }

      return jsonResponse({

        ok:
          true,

        service:
          "ProShape Mercado Pago Webhook",

        environment:
          environment.name,

        security:
          "signature-validation-enabled",

        mercadoPagoApi:
          "enabled",

        planIdentification:
          "enabled"
      });
    }


    /*
     * ========================================================
     * SOMENTE POST
     * ========================================================
     */

    if (
      request.method !==
      "POST"
    ) {

      return jsonResponse(
        {

          ok:
            false,

          error:
            "Method Not Allowed"
        },

        405
      );
    }


    try {

      /*
       * ======================================================
       * 1. VALIDAR ASSINATURA
       * ======================================================
       */

      const validSignature =
        await validateMercadoPagoSignature(
          request,
          environment.webhookSecret,
          environment.name
        );


      if (
        !validSignature
      ) {

        console.warn(
          `Webhook ${environment.name} rejeitado: assinatura inválida`
        );


        return jsonResponse(
          {

            received:
              false,

            validated:
              false,

            environment:
              environment.name,

            error:
              "Invalid signature"
          },

          401
        );
      }


      /*
       * ======================================================
       * 2. LER BODY
       * ======================================================
       */

      let body =
        {};


      try {

        body =
          await request.json();

      } catch {

        console.warn(
          `Webhook ${environment.name}: corpo JSON vazio ou inválido`
        );


        return jsonResponse({

          received:
            true,

          validated:
            true,

          environment:
            environment.name,

          processed:
            false,

          reason:
            "Body JSON inválido ou vazio"
        });
      }


      /*
       * ======================================================
       * 3. IDENTIFICAR EVENTO
       * ======================================================
       */

      const queryType =
        url.searchParams.get(
          "type"
        ) ||
        "";


      const bodyType =
        body?.type ||
        "";


      /*
       * Query possui prioridade.
       */

      const topic =
        queryType ||
        bodyType;


      const entity =
        body?.entity ||
        "";


      const action =
        body?.action ||
        "";


      /*
       * ID da URL
       */

      const queryDataId =
        url.searchParams.get(
          "data.id"
        );


      /*
       * ID do body
       */

      const bodyDataId =
        body?.data?.id ||
        body?.id ||
        null;


      /*
       * Prioridade URL
       */

      const dataId =
        queryDataId ||
        bodyDataId;


      console.log(
        "Webhook Mercado Pago validado:",
        JSON.stringify({

          environment:
            environment.name,

          queryType,

          bodyType,

          topic,

          entity,

          action,

          dataId,

          queryDataId:
            queryDataId ??
            null,

          bodyDataId:
            bodyDataId ??
            null
        })
      );


      /*
       * ======================================================
       * 4. SEM DATA ID
       * ======================================================
       */

      if (
        !dataId
      ) {

        return jsonResponse({

          received:
            true,

          validated:
            true,

          environment:
            environment.name,

          processed:
            false,

          reason:
            "Evento sem data.id"
        });
      }


      /*
       * ======================================================
       * 5. SIMULADOR
       * ======================================================
       */

      if (
        String(
          dataId
        ) ===
        "123456"
      ) {

        console.log(
          "Simulação Mercado Pago recebida:",
          JSON.stringify({

            environment:
              environment.name,

            topic,

            bodyType,

            action,

            dataId
          })
        );


        return jsonResponse({

          received:
            true,

          validated:
            true,

          simulated:
            true,

          environment:
            environment.name,

          topic,

          dataId
        });
      }


      /*
       * ======================================================
       * 6. PAGAMENTO AUTORIZADO DA ASSINATURA
       * ======================================================
       *
       * Este é o evento usado para liberar/renovar o acesso.
       *
       * Fluxo:
       * authorized_payment
       *      -> payment
       *      -> preapproval
       *      -> plano
       *      -> aluno
       *      -> renovação idempotente
       * ======================================================
       */

      if (
        topic ===
        "subscription_authorized_payment"
      ) {

        const authorizedPayment =
          await getAuthorizedPayment(
            dataId,
            environment.accessToken
          );

        const authorizedSummary =
          authorizedPaymentSummary(
            authorizedPayment
          );


        let payment =
          null;

        let paymentDataSummary =
          null;


        if (
          authorizedSummary.paymentId
        ) {
          payment =
            await getPayment(
              authorizedSummary.paymentId,
              environment.accessToken
            );

          paymentDataSummary =
            paymentSummary(
              payment
            );
        }


        let subscription =
          null;

        let subscriptionDataSummary =
          null;


        if (
          authorizedSummary.preapprovalId
        ) {
          subscription =
            await getSubscription(
              authorizedSummary.preapprovalId,
              environment.accessToken
            );

          subscriptionDataSummary =
            subscriptionSummary(
              subscription
            );
        }


        const plan =
          identifyProShapePlan(
            environment.name,
            subscriptionDataSummary
              ?.planId
          );


        const planValidation =
          validatePlanConfiguration(
            plan,
            subscriptionDataSummary
          );


        const automation =
          await processProShapeSubscriptionPayment({
            env,
            environmentName:
              environment.name,
            topic,
            authorizedPaymentSummaryData:
              authorizedSummary,
            paymentSummaryData:
              paymentDataSummary,
            subscriptionSummaryData:
              subscriptionDataSummary,
            plan,
            planValidation
          });


        console.log(
          "Pagamento recorrente de assinatura processado:",
          JSON.stringify({
            environment:
              environment.name,

            authorizedPayment:
              authorizedSummary,

            payment:
              paymentDataSummary,

            subscription:
              subscriptionDataSummary,

            plan:
              plan?.key ??
              null,

            planValidation,

            automation
          })
        );


        return jsonResponse({

          received:
            true,

          validated:
            true,

          environment:
            environment.name,

          processed:
            true,

          resource:
            "subscription_authorized_payment",

          authorizedPayment:
            authorizedSummary,

          payment:
            paymentDataSummary,

          subscription:
            subscriptionDataSummary,

          plan,

          planValidation,

          automation
        });
      }


      /*
       * ======================================================
       * 7. PAGAMENTO
       * ======================================================
       */

      if (
        topic ===
          "payment" ||

        bodyType ===
          "payment" ||

        action.startsWith(
          "payment."
        )
      ) {

        const payment =
          await getPayment(
            dataId,
            environment.accessToken
          );


        const summary =
          paymentSummary(
            payment
          );


        console.log(
          "Pagamento consultado:",
          JSON.stringify({

            environment:
              environment.name,

            ...summary
          })
        );


        /*
         * PAGAMENTO APROVADO
         */

        if (
          summary.status ===
          "approved"
        ) {

          console.log(
            "PAGAMENTO APROVADO:",
            JSON.stringify({

              environment:
                environment.name,

              ...summary
            })
          );
        }


        return jsonResponse({

          received:
            true,

          validated:
            true,

          environment:
            environment.name,

          processed:
            true,

          resource:
            "payment",

          payment:
            summary,

          automation: {
            processed:
              false,

            reason:
              "A liberação automática usa subscription_authorized_payment para evitar duplicidade ou pagamento não relacionado."
          }
        });
      }


      /*
       * ======================================================
       * 8. ASSINATURA / PREAPPROVAL
       * ======================================================
       */

      if (
        topic ===
          "subscription_preapproval" ||

        topic ===
          "preapproval" ||

        entity ===
          "preapproval"
      ) {

        /*
         * Consultar assinatura real.
         */

        const subscription =
          await getSubscription(
            dataId,
            environment.accessToken
          );


        const summary =
          subscriptionSummary(
            subscription
          );


        /*
         * IDENTIFICAR PLANO
         */

        const plan =
          identifyProShapePlan(
            environment.name,
            summary.planId
          );


        /*
         * VALIDAR VALOR + FREQUÊNCIA
         */

        const planValidation =
          validatePlanConfiguration(
            plan,
            summary
          );


        /*
         * LOG DA ASSINATURA
         */

        console.log(
          "Assinatura consultada:",
          JSON.stringify({

            environment:
              environment.name,

            ...summary
          })
        );


        /*
         * ====================================================
         * IDENTIFICAÇÃO PROSHAPE
         * ====================================================
         */

        const proShapeData = {

          cliente:
            summary.payerEmail,

          assinaturaId:
            summary.id,

          status:
            summary.status,

          planoId:
            summary.planId,

          plano:
            plan?.key ??
            "desconhecido",

          planoNome:
            plan?.name ??
            "Plano não identificado",

          valor:
            summary
              .autoRecurring
              ?.transactionAmount ??
            null,

          moeda:
            summary
              .autoRecurring
              ?.currencyId ??
            null,

          frequencia:
            summary
              .autoRecurring
              ?.frequency ??
            null,

          tipoFrequencia:
            summary
              .autoRecurring
              ?.frequencyType ??
            null,

          proximaCobranca:
            summary.nextPaymentDate,

          planoValidado:
            planValidation.valid
        };


        console.log(
          "Assinatura ProShape identificada:",
          JSON.stringify({
            environment:
              environment.name,

            ...proShapeData
          })
        );


        /*
         * ====================================================
         * PLANO NÃO RECONHECIDO
         * ====================================================
         */

        if (!plan) {

          console.warn(
            "PLANO PROSHAPE NÃO IDENTIFICADO:",
            JSON.stringify({

              environment:
                environment.name,

              planId:
                summary.planId,

              subscriptionId:
                summary.id,

              payerEmail:
                summary.payerEmail
            })
          );
        }


        /*
         * ====================================================
         * PLANO COM CONFIGURAÇÃO DIVERGENTE
         * ====================================================
         */

        if (
          plan &&
          !planValidation.valid
        ) {

          console.warn(
            "CONFIGURAÇÃO DO PLANO DIVERGENTE:",
            JSON.stringify({

              environment:
                environment.name,

              plan,

              received:
                summary.autoRecurring,

              validation:
                planValidation
            })
          );
        }


        /*
         * ====================================================
         * ASSINATURA ATIVA E PLANO VÁLIDO
         * ====================================================
         */

        if (
          plan &&
          planValidation.valid &&
          summary.status ===
            "authorized"
        ) {

          console.log(
            "ASSINATURA PROSHAPE ATIVA:",
            JSON.stringify({

              environment:
                environment.name,

              cliente:
                summary.payerEmail,

              plano:
                plan.key,

              planoNome:
                plan.name,

              assinaturaId:
                summary.id,

              proximaCobranca:
                summary.nextPaymentDate
            })
          );


          /*
           * ================================================
           * IMPORTANTE
           * ================================================
           *
           * A assinatura autorizada, sozinha, NÃO libera
           * acesso. A liberação ocorre somente quando chega
           * subscription_authorized_payment com pagamento
           * realmente aprovado.
           *
           * Isso evita liberar acesso sem cobrança aprovada.
           * ================================================
           */
        }


        return jsonResponse({

          received:
            true,

          validated:
            true,

          environment:
            environment.name,

          processed:
            true,

          resource:
            "subscription",

          subscription:
            summary,

          proShape:
            proShapeData,

          plan:
            plan,

          planValidation:
            planValidation
        });
      }


      /*
       * ======================================================
       * 9. OUTROS EVENTOS SUBSCRIPTION_*
       * ======================================================
       */

      if (
        topic.startsWith(
          "subscription_"
        )
      ) {

        console.log(
          "Evento de assinatura recebido:",
          JSON.stringify({

            environment:
              environment.name,

            topic,

            bodyType,

            action,

            dataId
          })
        );


        return jsonResponse({

          received:
            true,

          validated:
            true,

          environment:
            environment.name,

          processed:
            true,

          resource:
            "subscription_event",

          topic,

          dataId
        });
      }


      /*
       * ======================================================
       * 10. EVENTOS NÃO UTILIZADOS
       * ======================================================
       */

      console.log(
        "Evento válido não utilizado:",
        JSON.stringify({

          environment:
            environment.name,

          topic,

          bodyType,

          entity,

          action,

          dataId
        })
      );


      return jsonResponse({

        received:
          true,

        validated:
          true,

        environment:
          environment.name,

        processed:
          false,

        reason:
          "Evento não utilizado pela ProShape"
      });


    } catch (
      error
    ) {

      console.error(
        "Erro no webhook ProShape:",
        error instanceof Error
          ? error.message
          : String(error)
      );


      return jsonResponse(
        {

          received:
            false,

          environment:
            environment.name,

          error:
            "Webhook processing error",

          details:
            error instanceof Error
              ? error.message
              : String(error)
        },

        500
      );
    }
  }
};

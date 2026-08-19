import { Client } from "pg";

const encoder = new TextEncoder();

/*
 * ============================================================
 * PROSHAPE - MERCADO PAGO + POSTGRESQL
 * ============================================================
 *
 * PRODUÇÃO:
 * /
 *
 * TESTE:
 * /test
 *
 * HEALTH CHECK:
 * /db-health
 *
 * ============================================================
 */


/*
 * ============================================================
 * PLANOS
 * ============================================================
 */

const PROSHAPE_PLANS = {
  production: {
    d27387971674447895c70022508e5bb4: {
      key: "mensal",
      name: "ProShape Mensal",
      amount: 29.90,
      frequency: 1,
      frequencyType: "months",
      days: 30
    },

    "19b9f24a0abf459386c5a706b18d0e9a": {
      key: "trimestral",
      name: "ProShape Trimestral",
      amount: 84.90,
      frequency: 3,
      frequencyType: "months",
      days: 90
    },

    "153a4b17b65e445283b94a37fc4a5b0e": {
      key: "anual",
      name: "ProShape Anual",
      amount: 299.90,
      frequency: 12,
      frequencyType: "months",
      days: 365
    }
  },

  test: {
    "0b787e8eb57c4fcdb615d2c7fa18a510": {
      key: "mensal",
      name: "ProShape Mensal",
      amount: 29.90,
      frequency: 1,
      frequencyType: "months",
      days: 30
    },

    "69b9bf7b9b334157bd285392171316ea": {
      key: "trimestral",
      name: "ProShape Trimestral",
      amount: 84.90,
      frequency: 3,
      frequencyType: "months",
      days: 90
    },

    "7fd0f1dcfdbb461e96c8f74cb66c81d4": {
      key: "anual",
      name: "ProShape Anual",
      amount: 299.90,
      frequency: 12,
      frequencyType: "months",
      days: 365
    }
  }
};


/*
 * ============================================================
 * RESPOSTA JSON
 * ============================================================
 */

function jsonResponse(data, status = 200) {
  return new Response(
    JSON.stringify(data, null, 2),
    {
      status,
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "cache-control": "no-store"
      }
    }
  );
}


/*
 * ============================================================
 * AMBIENTE
 * ============================================================
 */

function getEnvironment(url, env) {
  const pathname =
    url.pathname.replace(/\/+$/, "") || "/";

  if (pathname === "/test") {
    return {
      name: "test",
      accessToken:
        env.MERCADO_PAGO_TEST_ACCESS_TOKEN,
      webhookSecret:
        env.MERCADO_PAGO_TEST_WEBHOOK_SECRET
    };
  }

  return {
    name: "production",
    accessToken:
      env.MERCADO_PAGO_ACCESS_TOKEN,
    webhookSecret:
      env.MERCADO_PAGO_WEBHOOK_SECRET
  };
}


/*
 * ============================================================
 * IDENTIFICAR PLANO
 * ============================================================
 */

function identifyPlan(environmentName, planId) {
  if (!planId) {
    return null;
  }

  const plans =
    PROSHAPE_PLANS[environmentName];

  if (!plans) {
    return null;
  }

  const plan =
    plans[String(planId)];

  if (!plan) {
    return null;
  }

  return {
    id: String(planId),
    ...plan
  };
}


/*
 * ============================================================
 * ASSINATURA HMAC
 * ============================================================
 */

function parseSignatureHeader(header) {
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
      result.ts = value;
    }

    if (key === "v1") {
      result.v1 = value;
    }
  }

  return result;
}


function hexToBytes(hex) {
  if (!hex) {
    return null;
  }

  const normalized =
    String(hex)
      .trim()
      .toLowerCase();

  if (
    !normalized ||
    normalized.length % 2 !== 0 ||
    !/^[0-9a-f]+$/.test(normalized)
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
        normalized.slice(i, i + 2),
        16
      );
  }

  return bytes;
}


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
    new URL(request.url);

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

  if (!ts || !v1) {
    console.warn(
      `Webhook ${environmentName}: assinatura ausente`
    );

    return false;
  }

  let dataId =
    url.searchParams.get(
      "data.id"
    );

  if (dataId) {
    dataId =
      String(dataId)
        .toLowerCase();
  }

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

  const key =
    await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["verify"]
    );

  const signatureBytes =
    hexToBytes(v1);

  if (!signatureBytes) {
    return false;
  }

  const valid =
    await crypto.subtle.verify(
      "HMAC",
      key,
      signatureBytes,
      encoder.encode(manifest)
    );

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
        method: "GET",

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

  let data = null;

  try {
    data =
      text
        ? JSON.parse(text)
        : null;
  } catch {
    data = {
      raw: text
    };
  }

  if (!response.ok) {
    throw new Error(
      `Mercado Pago API ${response.status}: ${text}`
    );
  }

  return data;
}


async function getPayment(
  id,
  accessToken
) {
  return mercadoPagoGet(
    `/v1/payments/${encodeURIComponent(id)}`,
    accessToken
  );
}


async function getSubscription(
  id,
  accessToken
) {
  return mercadoPagoGet(
    `/preapproval/${encodeURIComponent(id)}`,
    accessToken
  );
}


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
 * RESUMOS
 * ============================================================
 */

function paymentSummary(payment) {
  return {
    id:
      payment?.id ?? null,

    status:
      payment?.status ?? null,

    statusDetail:
      payment?.status_detail ?? null,

    amount:
      payment?.transaction_amount ?? null,

    currency:
      payment?.currency_id ?? null,

    externalReference:
      payment?.external_reference ?? null,

    description:
      payment?.description ?? null,

    payer: {
      id:
        payment?.payer?.id ?? null,

      email:
        payment?.payer?.email ?? null,

      firstName:
        payment?.payer?.first_name ?? null,

      lastName:
        payment?.payer?.last_name ?? null
    },

    dateApproved:
      payment?.date_approved ?? null,

    paymentMethod:
      payment?.payment_method_id ?? null
  };
}


function subscriptionSummary(
  subscription
) {
  return {
    id:
      subscription?.id ?? null,

    status:
      subscription?.status ?? null,

    reason:
      subscription?.reason ?? null,

    externalReference:
      subscription?.external_reference ??
      null,

    planId:
      subscription?.preapproval_plan_id ??
      null,

    payerId:
      subscription?.payer_id ??
      null,

    payerEmail:
      subscription?.payer_email ??
      null,

    dateCreated:
      subscription?.date_created ??
      null,

    nextPaymentDate:
      subscription?.next_payment_date ??
      null,

    autoRecurring:
      subscription?.auto_recurring
        ? {
            frequency:
              subscription
                .auto_recurring
                .frequency ?? null,

            frequencyType:
              subscription
                .auto_recurring
                .frequency_type ?? null,

            transactionAmount:
              subscription
                .auto_recurring
                .transaction_amount ??
              null,

            currencyId:
              subscription
                .auto_recurring
                .currency_id ?? null
          }
        : null
  };
}


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

    preapprovalId:
      authorizedPayment
        ?.preapproval_id ??
      null,

    externalReference:
      authorizedPayment
        ?.external_reference ??
      null,

    currency:
      authorizedPayment
        ?.currency_id ??
      null,

    amount:
      authorizedPayment
        ?.transaction_amount ??
      null,

    debitDate:
      authorizedPayment
        ?.debit_date ??
      null,

    paymentId:
      authorizedPayment
        ?.payment
        ?.id ??
      null,

    paymentStatus:
      authorizedPayment
        ?.payment
        ?.status ??
      null,

    paymentStatusDetail:
      authorizedPayment
        ?.payment
        ?.status_detail ??
      null
  };
}


/*
 * ============================================================
 * VALIDAÇÃO DO PLANO
 * ============================================================
 */

function validatePlan(
  plan,
  subscription
) {
  if (!plan || !subscription) {
    return {
      valid: false,
      reason:
        "Plano não identificado"
    };
  }

  const recurring =
    subscription.autoRecurring;

  if (!recurring) {
    return {
      valid: false,
      reason:
        "Recorrência ausente"
    };
  }

  const amountMatches =
    Math.abs(
      Number(
        recurring.transactionAmount
      ) -
      Number(plan.amount)
    ) < 0.01;

  const frequencyMatches =
    Number(
      recurring.frequency
    ) ===
    Number(
      plan.frequency
    );

  const frequencyTypeMatches =
    String(
      recurring.frequencyType
    ) ===
    String(
      plan.frequencyType
    );

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
 * DATA
 * ============================================================
 */

function todayBrazil() {
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

  const map =
    Object.fromEntries(
      parts.map(
        (part) => [
          part.type,
          part.value
        ]
      )
    );

  return (
    `${map.year}-${map.month}-${map.day}`
  );
}


function dateOnly(value) {
  if (!value) {
    return null;
  }

  const text =
    String(value);

  const match =
    text.match(
      /^(\d{4}-\d{2}-\d{2})/
    );

  return (
    match?.[1] ??
    null
  );
}


function addDays(
  dateString,
  days
) {
  const date =
    new Date(
      `${dateString}T12:00:00.000Z`
    );

  date.setUTCDate(
    date.getUTCDate() +
    Number(days)
  );

  return date
    .toISOString()
    .slice(0, 10);
}


function latestDate(a, b) {
  if (!a) {
    return b;
  }

  if (!b) {
    return a;
  }

  return (
    a >= b
      ? a
      : b
  );
}


/*
 * ============================================================
 * E-MAIL
 * ============================================================
 */

function normalizeEmail(value) {
  return String(
    value ?? ""
  )
    .trim()
    .toLowerCase();
}


/*
 * ============================================================
 * EXTERNAL REFERENCE
 * ============================================================
 */

function getStudentIdFromExternalReference(
  value
) {
  const reference =
    String(
      value ?? ""
    ).trim();

  if (
    reference.startsWith(
      "student:"
    )
  ) {
    return reference
      .slice(
        "student:".length
      )
      .trim();
  }

  return "";
}


/*
 * ============================================================
 * POSTGRESQL / HYPERDRIVE
 * ============================================================
 */

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


async function checkDatabase(
  env
) {
  const client =
    await createDatabaseClient(
      env
    );

  try {
    const result =
      await client.query(
        "SELECT 1 AS ok"
      );

    return (
      Number(
        result
          ?.rows
          ?.[0]
          ?.ok
      ) === 1
    );
  } finally {
    await client.end();
  }
}


/*
 * ============================================================
 * TABELA DE CONTROLE DE PAGAMENTOS
 * ============================================================
 */

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

      external_reference TEXT,
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

      PRIMARY KEY (
        environment,
        event_key
      )
    )
  `);

  await client.query(`
    CREATE INDEX IF NOT EXISTS
      proshape_payment_events_payment_idx
    ON
      proshape_payment_events (
        payment_id
      )
  `);

  await client.query(`
    CREATE INDEX IF NOT EXISTS
      proshape_payment_events_student_idx
    ON
      proshape_payment_events (
        student_id
      )
  `);
}


/*
 * ============================================================
 * LOCALIZAR ALUNO
 * ============================================================
 */

async function findStudent(
  client,
  externalReference,
  payerEmail
) {
  const externalStudentId =
    getStudentIdFromExternalReference(
      externalReference
    );

  /*
   * PRIORIDADE 1:
   * ID exato na external_reference
   */

  if (externalStudentId) {
    const result =
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
          WHERE id = $1
          LIMIT 1
          FOR UPDATE
        `,
        [
          externalStudentId
        ]
      );

    if (
      result.rows.length === 1
    ) {
      return {
        status: "found",
        method:
          "external_reference",
        student:
          result.rows[0]
      };
    }

    return {
      status:
        "not_found",

      method:
        "external_reference",

      student:
        null
    };
  }

  /*
   * PRIORIDADE 2:
   * E-mail
   */

  if (!payerEmail) {
    return {
      status:
        "not_found",

      method:
        "email",

      student:
        null
    };
  }

  const result =
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
          LOWER(
            TRIM(email)
          ) = $1
        ORDER BY
          created_at ASC
        LIMIT 2
        FOR UPDATE
      `,
      [
        payerEmail
      ]
    );

  if (
    result.rows.length === 0
  ) {
    return {
      status:
        "not_found",

      method:
        "email",

      student:
        null
    };
  }

  /*
   * Segurança:
   * dois alunos com o mesmo e-mail.
   */

  if (
    result.rows.length > 1
  ) {
    return {
      status:
        "duplicate_email",

      method:
        "email",

      student:
        null
    };
  }

  return {
    status:
      "found",

    method:
      "email",

    student:
      result.rows[0]
  };
}


/*
 * ============================================================
 * REGISTRAR RESULTADO DO EVENTO
 * ============================================================
 */

async function updateEventResult(
  client,
  environmentName,
  eventKey,
  {
    processed = false,
    result,
    studentId = null
  }
) {
  await client.query(
    `
      UPDATE
        proshape_payment_events
      SET
        processed = $1,
        result = $2,
        student_id = $3,
        updated_at = NOW()
      WHERE
        environment = $4
        AND event_key = $5
    `,
    [
      processed,
      result,
      studentId,
      environmentName,
      eventKey
    ]
  );
}


/*
 * ============================================================
 * PROCESSAR RENOVAÇÃO
 * ============================================================
 */

async function processSubscriptionPayment({
  env,
  environmentName,
  topic,
  authorizedPayment,
  payment,
  subscription,
  plan,
  planValidation
}) {
  const paymentId =
    payment?.id
      ? String(payment.id)
      : authorizedPayment
          ?.paymentId
        ? String(
            authorizedPayment
              .paymentId
          )
        : "";

  const authorizedPaymentId =
    authorizedPayment?.id
      ? String(
          authorizedPayment.id
        )
      : "";

  const subscriptionId =
    subscription?.id
      ? String(
          subscription.id
        )
      : authorizedPayment
          ?.preapprovalId
        ? String(
            authorizedPayment
              .preapprovalId
          )
        : "";

  const eventKey =
    paymentId
      ? `payment:${paymentId}`
      : authorizedPaymentId
        ? `authorized:${authorizedPaymentId}`
        : "";

  if (!eventKey) {
    return {
      ok: false,
      processed: false,
      result:
        "missing_event_id"
    };
  }

  const paymentStatus =
    payment?.status ??
    authorizedPayment
      ?.paymentStatus ??
    null;

  const externalReference =
    String(
      subscription
        ?.externalReference ??
      payment
        ?.externalReference ??
      authorizedPayment
        ?.externalReference ??
      ""
    ).trim();

  const payerEmail =
    normalizeEmail(
      subscription
        ?.payerEmail ??
      payment
        ?.payer
        ?.email ??
      ""
    );

  const amount =
    Number(
      payment?.amount ??
      authorizedPayment?.amount ??
      0
    );

  const currency =
    payment?.currency ??
    authorizedPayment
      ?.currency ??
    null;


  /*
   * PAGAMENTO PRECISA ESTAR APROVADO
   */

  if (
    paymentStatus !== "approved"
  ) {
    return {
      ok: true,
      processed: false,
      result:
        "payment_not_approved",
      paymentStatus
    };
  }


  /*
   * PLANO PRECISA SER VÁLIDO
   */

  if (
    !plan ||
    !planValidation?.valid
  ) {
    return {
      ok: true,
      processed: false,
      result:
        "invalid_plan"
    };
  }


  /*
   * VALOR DO PAGAMENTO
   */

  if (
    amount &&
    Math.abs(
      amount -
      Number(plan.amount)
    ) >= 0.01
  ) {
    return {
      ok: true,
      processed: false,
      result:
        "invalid_payment_amount",
      receivedAmount:
        amount,
      expectedAmount:
        plan.amount
    };
  }


  /*
   * MOEDA
   */

  if (
    currency &&
    String(currency) !==
      "BRL"
  ) {
    return {
      ok: true,
      processed: false,
      result:
        "invalid_currency"
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
       * CRIAR / ATUALIZAR EVENTO
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
            external_reference,
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
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            $11,
            $12,
            $13,
            FALSE,
            'received',
            NOW()
          )

          ON CONFLICT (
            environment,
            event_key
          )

          DO UPDATE SET
            topic =
              EXCLUDED.topic,

            authorized_payment_id =
              EXCLUDED.authorized_payment_id,

            payment_id =
              EXCLUDED.payment_id,

            subscription_id =
              EXCLUDED.subscription_id,

            external_reference =
              EXCLUDED.external_reference,

            payer_email =
              EXCLUDED.payer_email,

            plan_key =
              EXCLUDED.plan_key,

            plan_name =
              EXCLUDED.plan_name,

            amount =
              EXCLUDED.amount,

            currency =
              EXCLUDED.currency,

            payment_status =
              EXCLUDED.payment_status,

            updated_at =
              NOW()
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

          externalReference ||
            null,

          payerEmail ||
            null,

          plan.key,
          plan.name,

          amount ||
            null,

          currency,
          paymentStatus
        ]
      );


      /*
       * TRAVAR EVENTO
       */

      const eventResult =
        await client.query(
          `
            SELECT
              processed,
              result,
              student_id
            FROM
              proshape_payment_events
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

      const existing =
        eventResult.rows[0];


      /*
       * IDEMPOTÊNCIA
       *
       * Se já processamos este paymentId,
       * não renova novamente.
       */

      if (
        existing?.processed ===
        true
      ) {
        await client.query(
          "COMMIT"
        );

        return {
          ok: true,
          processed: true,
          duplicate: true,
          result:
            existing.result,
          studentId:
            existing.student_id ??
            null,
          paymentId:
            paymentId ||
            null,
          plan:
            plan.key
        };
      }


      /*
       * TESTE:
       *
       * Não altera nenhum aluno real.
       */

      if (
        environmentName ===
        "test"
      ) {
        await updateEventResult(
          client,
          environmentName,
          eventKey,
          {
            processed: true,
            result:
              "dry_run_test"
          }
        );

        await client.query(
          "COMMIT"
        );

        console.log(
          "PAGAMENTO TESTE VALIDADO - DRY RUN:",
          JSON.stringify({
            paymentId,
            subscriptionId,
            payerEmail,
            plan:
              plan.key
          })
        );

        return {
          ok: true,
          processed: true,
          dryRun: true,
          duplicate: false,
          result:
            "dry_run_test",
          paymentId:
            paymentId ||
            null,
          payerEmail,
          plan:
            plan.key
        };
      }


      /*
       * PRODUÇÃO:
       * localizar aluno.
       */

      const lookup =
        await findStudent(
          client,
          externalReference,
          payerEmail
        );


      /*
       * NÃO ENCONTROU
       */

      if (
        lookup.status ===
        "not_found"
      ) {
        await updateEventResult(
          client,
          environmentName,
          eventKey,
          {
            processed: false,
            result:
              "student_not_found"
          }
        );

        await client.query(
          "COMMIT"
        );

        console.warn(
          "ALUNO NÃO ENCONTRADO:",
          JSON.stringify({
            paymentId,
            payerEmail,
            externalReference,
            plan:
              plan.key
          })
        );

        return {
          ok: true,
          processed: false,
          result:
            "student_not_found",
          payerEmail,
          paymentId:
            paymentId ||
            null
        };
      }


      /*
       * E-MAIL DUPLICADO
       */

      if (
        lookup.status ===
        "duplicate_email"
      ) {
        await updateEventResult(
          client,
          environmentName,
          eventKey,
          {
            processed: false,
            result:
              "duplicate_student_email"
          }
        );

        await client.query(
          "COMMIT"
        );

        console.warn(
          "E-MAIL DUPLICADO NO PROSHAPE:",
          payerEmail
        );

        return {
          ok: true,
          processed: false,
          result:
            "duplicate_student_email",
          payerEmail
        };
      }


      const student =
        lookup.student;

      const today =
        todayBrazil();

      const oldExpiry =
        dateOnly(
          student.expires_at
        );

      const nextPaymentDate =
        dateOnly(
          subscription
            ?.nextPaymentDate
        );


      /*
       * DEFINIR NOVO VENCIMENTO
       *
       * Preferência:
       * próxima cobrança do Mercado Pago.
       *
       * Fallback:
       * 30 / 90 / 365 dias.
       */

      let newExpiry;

      if (
        nextPaymentDate &&
        nextPaymentDate > today
      ) {
        newExpiry =
          latestDate(
            oldExpiry,
            nextPaymentDate
          );
      } else {
        const base =
          oldExpiry &&
          oldExpiry >= today
            ? oldExpiry
            : today;

        newExpiry =
          addDays(
            base,
            plan.days
          );
      }


      /*
       * ATUALIZAR ALUNO
       */

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


      /*
       * MARCAR EVENTO COMO PROCESSADO
       */

      await updateEventResult(
        client,
        environmentName,
        eventKey,
        {
          processed: true,
          result:
            "access_renewed",
          studentId:
            student.id
        }
      );

      await client.query(
        "COMMIT"
      );


      /*
       * LOG
       */

      console.log(
        "ACESSO PROSHAPE RENOVADO:",
        JSON.stringify({
          studentId:
            updatedStudent.id,

          studentName:
            updatedStudent.name,

          lookupMethod:
            lookup.method,

          payerEmail,

          paymentId,

          subscriptionId,

          plan:
            plan.key,

          paidAt:
            updatedStudent.paid_at,

          expiresAt:
            updatedStudent.expires_at
        })
      );


      return {
        ok: true,

        processed: true,

        duplicate: false,

        result:
          "access_renewed",

        lookupMethod:
          lookup.method,

        paymentId:
          paymentId ||
          null,

        subscriptionId:
          subscriptionId ||
          null,

        plan:
          plan.key,

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
        }
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
      // Sem ação.
    }
  }
}


/*
 * ============================================================
 * WORKER
 * ============================================================
 */

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    /*
     * ========================================================
     * HEALTH CHECK
     * ========================================================
     */

    if (
      request.method === "GET" &&
      url.pathname
        .replace(/\/+$/, "") ===
        "/db-health"
    ) {
      try {
        const connected =
          await checkDatabase(env);

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
          "Erro no banco:",
          error instanceof Error
            ? error.message
            : String(error)
        );

        return jsonResponse(
          {
            ok: false,
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


    /*
     * ========================================================
     * AMBIENTE
     * ========================================================
     */

    const environment =
      getEnvironment(
        url,
        env
      );


    /*
     * ========================================================
     * GET NORMAL
     * ========================================================
     */

    if (
      request.method === "GET"
    ) {
      return jsonResponse({
        ok: true,

        service:
          "ProShape Mercado Pago Webhook",

        environment:
          environment.name,

        security:
          "signature-validation-enabled",

        mercadoPagoApi:
          "enabled",

        database:
          "Hyperdrive",

        automation:
          environment.name ===
            "test"
            ? "dry-run"
            : "production"
      });
    }


    /*
     * ========================================================
     * APENAS POST
     * ========================================================
     */

    if (
      request.method !==
      "POST"
    ) {
      return jsonResponse(
        {
          ok: false,
          error:
            "Method Not Allowed"
        },
        405
      );
    }


    try {

      /*
       * ======================================================
       * VALIDAR ASSINATURA
       * ======================================================
       */

      const validSignature =
        await validateMercadoPagoSignature(
          request,
          environment.webhookSecret,
          environment.name
        );

      if (!validSignature) {
        return jsonResponse(
          {
            received: false,
            validated: false,
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
       * BODY
       * ======================================================
       */

      let body = {};

      try {
        body =
          await request.json();
      } catch {
        return jsonResponse({
          received: true,
          validated: true,
          environment:
            environment.name,
          processed: false,
          reason:
            "Body JSON inválido ou vazio"
        });
      }


      /*
       * ======================================================
       * EVENTO
       * ======================================================
       */

      const queryType =
        url.searchParams.get(
          "type"
        ) || "";

      const bodyType =
        body?.type || "";

      const topic =
        queryType ||
        bodyType;

      const entity =
        body?.entity || "";

      const action =
        body?.action || "";

      const queryDataId =
        url.searchParams.get(
          "data.id"
        );

      const bodyDataId =
        body?.data?.id ??
        body?.id ??
        null;

      const dataId =
        queryDataId ||
        bodyDataId;


      console.log(
        "Webhook recebido:",
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


      /*
       * ======================================================
       * SEM ID
       * ======================================================
       */

      if (!dataId) {
        return jsonResponse({
          received: true,
          validated: true,
          environment:
            environment.name,
          processed: false,
          reason:
            "Evento sem data.id"
        });
      }


      /*
       * ======================================================
       * SIMULADOR MERCADO PAGO
       * ======================================================
       *
       * O simulador usa 123456.
       * Não consulta a API real.
       * ======================================================
       */

      if (
        String(dataId) ===
        "123456"
      ) {
        console.log(
          "Simulação Mercado Pago aceita:",
          JSON.stringify({
            environment:
              environment.name,
            topic,
            dataId
          })
        );

        return jsonResponse({
          received: true,
          validated: true,
          simulated: true,
          environment:
            environment.name,
          topic,
          dataId
        });
      }


      /*
       * ======================================================
       * PAGAMENTO RECORRENTE DA ASSINATURA
       * ======================================================
       */

      if (
        topic ===
        "subscription_authorized_payment"
      ) {
        const authorizedPaymentRaw =
          await getAuthorizedPayment(
            dataId,
            environment.accessToken
          );

        const authorizedPayment =
          authorizedPaymentSummary(
            authorizedPaymentRaw
          );


        /*
         * PAGAMENTO
         */

        let payment = null;

        if (
          authorizedPayment.paymentId
        ) {
          const rawPayment =
            await getPayment(
              authorizedPayment.paymentId,
              environment.accessToken
            );

          payment =
            paymentSummary(
              rawPayment
            );
        }


        /*
         * ASSINATURA
         */

        let subscription = null;

        if (
          authorizedPayment.preapprovalId
        ) {
          const rawSubscription =
            await getSubscription(
              authorizedPayment.preapprovalId,
              environment.accessToken
            );

          subscription =
            subscriptionSummary(
              rawSubscription
            );
        }


        /*
         * PLANO
         */

        const plan =
          identifyPlan(
            environment.name,
            subscription?.planId
          );

        const planValidation =
          validatePlan(
            plan,
            subscription
          );


        /*
         * AUTOMAÇÃO
         */

        const automation =
          await processSubscriptionPayment({
            env,

            environmentName:
              environment.name,

            topic,

            authorizedPayment,

            payment,

            subscription,

            plan,

            planValidation
          });


        console.log(
          "Resultado automação:",
          JSON.stringify({
            environment:
              environment.name,

            paymentId:
              payment?.id ??
              authorizedPayment
                .paymentId ??
              null,

            subscriptionId:
              subscription?.id ??
              null,

            plan:
              plan?.key ??
              null,

            automation
          })
        );


        return jsonResponse({
          received: true,

          validated: true,

          environment:
            environment.name,

          processed: true,

          resource:
            "subscription_authorized_payment",

          authorizedPayment,

          payment,

          subscription,

          plan,

          planValidation,

          automation
        });
      }


      /*
       * ======================================================
       * PAYMENT
       * ======================================================
       *
       * Consultamos e registramos.
       *
       * Não renovamos por esta notificação para evitar
       * duplicidade com subscription_authorized_payment.
       * ======================================================
       */

      if (
        topic === "payment" ||
        bodyType === "payment" ||
        action.startsWith(
          "payment."
        )
      ) {
        const rawPayment =
          await getPayment(
            dataId,
            environment.accessToken
          );

        const payment =
          paymentSummary(
            rawPayment
          );

        console.log(
          "Pagamento consultado:",
          JSON.stringify({
            environment:
              environment.name,
            ...payment
          })
        );

        return jsonResponse({
          received: true,

          validated: true,

          environment:
            environment.name,

          processed: true,

          resource:
            "payment",

          payment,

          automation: {
            processed: false,

            reason:
              "Renovação executada somente por subscription_authorized_payment para evitar duplicidade."
          }
        });
      }


      /*
       * ======================================================
       * PREAPPROVAL / ASSINATURA
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
        const rawSubscription =
          await getSubscription(
            dataId,
            environment.accessToken
          );

        const subscription =
          subscriptionSummary(
            rawSubscription
          );

        const plan =
          identifyPlan(
            environment.name,
            subscription.planId
          );

        const planValidation =
          validatePlan(
            plan,
            subscription
          );

        console.log(
          "Assinatura consultada:",
          JSON.stringify({
            environment:
              environment.name,

            subscriptionId:
              subscription.id,

            status:
              subscription.status,

            payerEmail:
              subscription.payerEmail,

            plan:
              plan?.key ??
              null,

            planValid:
              planValidation.valid
          })
        );

        return jsonResponse({
          received: true,

          validated: true,

          environment:
            environment.name,

          processed: true,

          resource:
            "subscription",

          subscription,

          plan,

          planValidation,

          automation: {
            processed: false,

            reason:
              "Autorização da assinatura não libera acesso. A renovação ocorre quando a cobrança recorrente estiver aprovada."
          }
        });
      }


      /*
       * ======================================================
       * OUTROS EVENTOS DE ASSINATURA
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
            dataId
          })
        );

        return jsonResponse({
          received: true,
          validated: true,
          environment:
            environment.name,
          processed: true,
          resource:
            "subscription_event",
          topic,
          dataId
        });
      }


      /*
       * ======================================================
       * EVENTO NÃO UTILIZADO
       * ======================================================
       */

      console.log(
        "Evento válido não utilizado:",
        JSON.stringify({
          environment:
            environment.name,
          topic,
          entity,
          action,
          dataId
        })
      );

      return jsonResponse({
        received: true,
        validated: true,
        environment:
          environment.name,
        processed: false,
        reason:
          "Evento não utilizado pela ProShape"
      });

    } catch (error) {
      console.error(
        "Erro no webhook ProShape:",
        error instanceof Error
          ? error.message
          : String(error)
      );

      return jsonResponse(
        {
          received: false,

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

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const port = process.env.PORT || 3000;
const publicDir = __dirname;
const databaseUrl = process.env.DATABASE_URL;

let pool = null;
if (databaseUrl) {
  const { Pool } = require("pg");
  pool = new Pool({
    connectionString: databaseUrl,
    ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : undefined
  });
}

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon"
};

function sendJson(response, status, data) {
  response.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(data));
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) {
        request.destroy();
        reject(new Error("Payload muito grande"));
      }
    });
    request.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error("JSON inválido"));
      }
    });
  });
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  const [salt, hash] = String(storedHash || "").split(":");
  if (!salt || !hash) return false;
  const testHash = crypto.scryptSync(password, salt, 64);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), testHash);
}

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

function currentMonthRef() {
  const now = new Date();
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}-01`;
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || ""));
}

async function ensureDatabase() {
  if (!pool) return;
  await pool.query(`
    CREATE EXTENSION IF NOT EXISTS pgcrypto;

    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name VARCHAR(120) NOT NULL,
      email VARCHAR(180) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_sessions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_profiles (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      monthly_salary NUMERIC(12, 2) NOT NULL DEFAULT 0 CHECK (monthly_salary >= 0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS financial_goals (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      month_ref DATE NOT NULL,
      target_amount NUMERIC(12, 2) NOT NULL DEFAULT 0 CHECK (target_amount >= 0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (user_id, month_ref)
    );

    CREATE TABLE IF NOT EXISTS expenses (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(160) NOT NULL,
      amount NUMERIC(12, 2) NOT NULL CHECK (amount > 0),
      category VARCHAR(60) NOT NULL,
      expense_date DATE NOT NULL,
      payment_method VARCHAR(40) NOT NULL,
      note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_expenses_user_date ON expenses(user_id, expense_date DESC);
    CREATE INDEX IF NOT EXISTS idx_expenses_user_category ON expenses(user_id, category);
    CREATE INDEX IF NOT EXISTS idx_expenses_user_payment ON expenses(user_id, payment_method);
    CREATE INDEX IF NOT EXISTS idx_goals_user_month ON financial_goals(user_id, month_ref);
  `);
}

function tokenHash(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function getAuthUser(request) {
  if (!pool) return null;
  const auth = request.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return null;

  const result = await pool.query(
    `SELECT users.id, users.name, users.email
       FROM user_sessions
       JOIN users ON users.id = user_sessions.user_id
      WHERE user_sessions.token_hash = $1
        AND user_sessions.expires_at > NOW()
      LIMIT 1`,
    [tokenHash(token)]
  );

  return result.rows[0] || null;
}

async function handleRegister(request, response) {
  if (!pool) {
    sendJson(response, 503, { error: "Banco de dados não configurado." });
    return;
  }

  const body = await readJsonBody(request);
  const name = String(body.name || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!name || !email || password.length < 6) {
    sendJson(response, 400, { error: "Informe nome, e-mail e uma senha com pelo menos 6 caracteres." });
    return;
  }

  try {
    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, name, email`,
      [name, email, hashPassword(password)]
    );

    await pool.query("INSERT INTO user_profiles (user_id) VALUES ($1) ON CONFLICT DO NOTHING", [result.rows[0].id]);
    const token = createToken();
    await pool.query(
      "INSERT INTO user_sessions (user_id, token_hash, expires_at) VALUES ($1, $2, NOW() + INTERVAL '30 days')",
      [result.rows[0].id, tokenHash(token)]
    );

    sendJson(response, 201, { user: result.rows[0], token });
  } catch (error) {
    if (error.code === "23505") {
      sendJson(response, 409, { error: "Esse e-mail já está cadastrado." });
      return;
    }
    throw error;
  }
}

async function handleLogin(request, response) {
  if (!pool) {
    sendJson(response, 503, { error: "Banco de dados não configurado." });
    return;
  }

  const body = await readJsonBody(request);
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  const result = await pool.query("SELECT id, name, email, password_hash FROM users WHERE email = $1 LIMIT 1", [email]);
  const user = result.rows[0];
  if (!user || !verifyPassword(password, user.password_hash)) {
    sendJson(response, 401, { error: "E-mail ou senha inválidos." });
    return;
  }

  const token = createToken();
  await pool.query(
    "INSERT INTO user_sessions (user_id, token_hash, expires_at) VALUES ($1, $2, NOW() + INTERVAL '30 days')",
    [user.id, tokenHash(token)]
  );

  sendJson(response, 200, { user: { id: user.id, name: user.name, email: user.email }, token });
}

async function handleMe(request, response) {
  const user = await getAuthUser(request);
  if (!user) {
    sendJson(response, 401, { error: "Sessão não encontrada." });
    return;
  }
  sendJson(response, 200, { user });
}

async function handleLogout(request, response) {
  if (pool) {
    const auth = request.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (token) await pool.query("DELETE FROM user_sessions WHERE token_hash = $1", [tokenHash(token)]);
  }
  sendJson(response, 200, { ok: true });
}

async function handleGetFinance(request, response) {
  const user = await getAuthUser(request);
  if (!user) {
    sendJson(response, 401, { error: "Sessão não encontrada." });
    return;
  }

  const monthRef = currentMonthRef();
  const [profileResult, goalResult, expensesResult] = await Promise.all([
    pool.query("SELECT monthly_salary FROM user_profiles WHERE user_id = $1 LIMIT 1", [user.id]),
    pool.query(
      "SELECT target_amount FROM financial_goals WHERE user_id = $1 AND month_ref = $2 LIMIT 1",
      [user.id, monthRef]
    ),
    pool.query(
      `SELECT id, name, amount, category, expense_date, payment_method, note
         FROM expenses
        WHERE user_id = $1
        ORDER BY expense_date DESC, created_at DESC`,
      [user.id]
    )
  ]);

  sendJson(response, 200, {
    salary: Number(profileResult.rows[0]?.monthly_salary || 0),
    monthlyGoal: Number(goalResult.rows[0]?.target_amount || 0),
    expenses: expensesResult.rows.map((expense) => {
      const date = expense.expense_date instanceof Date
        ? expense.expense_date.toISOString().slice(0, 10)
        : String(expense.expense_date).slice(0, 10);
      return {
        id: expense.id,
        name: expense.name,
        value: Number(expense.amount),
        category: expense.category,
        date,
        payment: expense.payment_method,
        note: expense.note || ""
      };
    })
  });
}

async function handleSaveFinance(request, response) {
  const user = await getAuthUser(request);
  if (!user) {
    sendJson(response, 401, { error: "Sessão não encontrada." });
    return;
  }

  const body = await readJsonBody(request);
  const salary = Math.max(Number(body.salary) || 0, 0);
  const monthlyGoal = Math.max(Number(body.monthlyGoal) || 0, 0);
  const incomingExpenses = Array.isArray(body.expenses) ? body.expenses : [];
  const monthRef = currentMonthRef();
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO user_profiles (user_id, monthly_salary)
       VALUES ($1, $2)
       ON CONFLICT (user_id)
       DO UPDATE SET monthly_salary = EXCLUDED.monthly_salary, updated_at = NOW()`,
      [user.id, salary]
    );
    await client.query(
      `INSERT INTO financial_goals (user_id, month_ref, target_amount)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, month_ref)
       DO UPDATE SET target_amount = EXCLUDED.target_amount, updated_at = NOW()`,
      [user.id, monthRef, monthlyGoal]
    );
    await client.query("DELETE FROM expenses WHERE user_id = $1", [user.id]);

    for (const expense of incomingExpenses) {
      const name = String(expense.name || "").trim();
      const amount = Number(expense.value) || 0;
      const category = String(expense.category || "Outros").trim();
      const date = String(expense.date || "").slice(0, 10);
      const payment = String(expense.payment || "Outro").trim();
      const note = String(expense.note || "").trim();
      if (!name || amount <= 0 || !date) continue;

      await client.query(
        `INSERT INTO expenses (id, user_id, name, amount, category, expense_date, payment_method, note)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [isUuid(expense.id) ? expense.id : crypto.randomUUID(), user.id, name, amount, category, date, payment, note]
      );
    }

    await client.query("COMMIT");
    sendJson(response, 200, { ok: true });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function serveStatic(request, response, url) {
  const requestedPath = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
  const filePath = path.normalize(path.join(publicDir, requestedPath));

  if (!filePath.startsWith(publicDir)) {
    response.writeHead(403);
    response.end("Acesso negado");
    return;
  }

  fs.readFile(filePath, (error, content) => {
    if (error) {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Arquivo não encontrado");
      return;
    }

    response.writeHead(200, {
      "Content-Type": mimeTypes[path.extname(filePath)] || "application/octet-stream"
    });
    response.end(content);
  });
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host}`);

  try {
    if (url.pathname === "/api/register" && request.method === "POST") return await handleRegister(request, response);
    if (url.pathname === "/api/login" && request.method === "POST") return await handleLogin(request, response);
    if (url.pathname === "/api/me" && request.method === "GET") return await handleMe(request, response);
    if (url.pathname === "/api/logout" && request.method === "POST") return await handleLogout(request, response);
    if (url.pathname === "/api/finance" && request.method === "GET") return await handleGetFinance(request, response);
    if (url.pathname === "/api/finance" && request.method === "PUT") return await handleSaveFinance(request, response);

    serveStatic(request, response, url);
  } catch (error) {
    console.error(error);
    sendJson(response, 500, { error: "Erro interno do servidor." });
  }
});

ensureDatabase()
  .then(() => {
    server.listen(port, () => {
      console.log(`Planilha financeira rodando na porta ${port}`);
    });
  })
  .catch((error) => {
    console.error("Erro ao preparar banco de dados:", error);
    process.exit(1);
  });

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

"use strict";

const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

for (const key of ["DATABASE_URL", "SESSION_SECRET", "ADMIN_PASSWORD"]) {
  if (!process.env[key]) {
    throw new Error(`${key} ntishyizwe muri Environment.`);
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "false"
    ? false
    : { rejectUnauthorized: false }
});

app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  name: "report1.sid",
  store: new PgSession({
    pool,
    tableName: "session",
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: "auto",
    sameSite: "lax",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const asyncRoute = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

const publicUser = u => ({
  id: u.id,
  username: u.username,
  name: u.name,
  role: u.role,
  branchId: u.branch_id ?? null
});

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Banza winjire muri system."
    });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.user?.role !== "admin") {
    return res.status(403).json({
      error: "Admin gusa yemerewe iki gikorwa."
    });
  }
  next();
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS branches (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE
    );

    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin', 'branch')),
      branch_id INTEGER REFERENCES branches(id),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (
        (role = 'admin' AND branch_id IS NULL) OR
        (role = 'branch' AND branch_id IS NOT NULL)
      )
    );

    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      selling_price NUMERIC(14,2) NOT NULL DEFAULT 0
        CHECK (selling_price >= 0),
      cost_price NUMERIC(14,2) NOT NULL DEFAULT 0
        CHECK (cost_price >= 0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS stock (
      branch_id INTEGER NOT NULL REFERENCES branches(id),
      product_id INTEGER NOT NULL REFERENCES products(id),
      quantity INTEGER NOT NULL DEFAULT 0 CHECK (quantity >= 0),
      PRIMARY KEY (branch_id, product_id)
    );

    CREATE TABLE IF NOT EXISTS warehouse_stock (
      product_id INTEGER PRIMARY KEY REFERENCES products(id),
      quantity INTEGER NOT NULL DEFAULT 0 CHECK (quantity >= 0)
    );

    CREATE TABLE IF NOT EXISTS warehouse_movements (
      id SERIAL PRIMARY KEY,
      product_id INTEGER NOT NULL REFERENCES products(id),
      quantity INTEGER NOT NULL CHECK (quantity > 0),
      user_id INTEGER NOT NULL REFERENCES users(id),
      details TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS transfers (
      id SERIAL PRIMARY KEY,
      product_id INTEGER NOT NULL REFERENCES products(id),
      to_branch INTEGER NOT NULL REFERENCES branches(id),
      quantity INTEGER NOT NULL CHECK (quantity > 0),
      user_id INTEGER NOT NULL REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sales (
      id SERIAL PRIMARY KEY,
      branch_id INTEGER NOT NULL REFERENCES branches(id),
      user_id INTEGER NOT NULL REFERENCES users(id),
      total NUMERIC(14,2) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sale_items (
      id SERIAL PRIMARY KEY,
      sale_id INTEGER NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
      product_id INTEGER NOT NULL REFERENCES products(id),
      quantity INTEGER NOT NULL CHECK (quantity > 0),
      unit_price NUMERIC(14,2) NOT NULL,
      line_total NUMERIC(14,2) NOT NULL
    );

    CREATE TABLE IF NOT EXISTS stock_movements (
      id SERIAL PRIMARY KEY,
      product_id INTEGER NOT NULL REFERENCES products(id),
      branch_id INTEGER NOT NULL REFERENCES branches(id),
      movement_type TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id),
      details TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    INSERT INTO branches(name)
    VALUES ('Ishami 1'), ('Ishami 2')
    ON CONFLICT (name) DO NOTHING
  `);

  const count = await pool.query(
    "SELECT COUNT(*)::int AS n FROM products"
  );

  if (count.rows[0].n === 0) {
    for (let i = 1; i <= 15; i++) {
      await pool.query(
        "INSERT INTO products(name) VALUES ($1) ON CONFLICT DO NOTHING",
        [`Igicuruzwa ${i}`]
      );
    }
  }

  await pool.query(`
    INSERT INTO stock(branch_id, product_id, quantity)
    SELECT b.id, p.id, 0
    FROM branches b CROSS JOIN products p
    ON CONFLICT DO NOTHING
  `);

  await pool.query(`
    INSERT INTO warehouse_stock(product_id, quantity)
    SELECT id, 0 FROM products
    ON CONFLICT DO NOTHING
  `);

  const username = process.env.ADMIN_USERNAME || "admin";
  const existing = await pool.query(
    "SELECT id FROM users WHERE username = $1",
    [username]
  );

  if (existing.rowCount === 0) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);

    await pool.query(
      `INSERT INTO users(username, password_hash, name, role)
       VALUES ($1, $2, 'Admin', 'admin')`,
      [username, hash]
    );

    console.log("Konti ya admin yakozwe.");
  }

  console.log("Database ya Report 1 yateguwe.");
}

app.get("/api/health", asyncRoute(async (req, res) => {
  await pool.query("SELECT 1");

  res.json({
    ok: true,
    app: "Report 1",
    database: "connected"
  });
}));

app.post("/api/login", asyncRoute(async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  const result = await pool.query(
    "SELECT * FROM users WHERE username = $1 AND active = TRUE",
    [username]
  );

  const user = result.rows[0];

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({
      error: "Izina cyangwa ijambo ry'ibanga si byo."
    });
  }

  req.session.regenerate(err => {
    if (err) {
      return res.status(500).json({
        error: "Ikibazo cya session."
      });
    }

    req.session.user = publicUser(user);

    req.session.save(saveErr => {
      if (saveErr) {
        return res.status(500).json({
          error: "Session ntiyabitswe."
        });
      }

      res.json({ user: req.session.user });
    });
  });
}));

app.get("/api/me", (req, res) => {
  res.json({ user: req.session.user || null });
});

app.post("/api/logout", requireLogin, (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);

    res.clearCookie("report1.sid");
    res.json({ ok: true });
  });
});

app.get("/api/data", requireLogin, asyncRoute(async (req, res) => {
  const user = req.session.user;

  const branches = await pool.query(
    "SELECT id, name FROM branches ORDER BY id"
  );

  const products = await pool.query(`
    SELECT p.id, p.name, p.selling_price,
           ${user.role === "admin" ? "p.cost_price," : ""}
           s.branch_id, s.quantity
    FROM products p
    JOIN stock s ON s.product_id = p.id
    ${user.role === "admin" ? "" : "WHERE s.branch_id = $1"}
    ORDER BY p.id, s.branch_id
  `, user.role === "admin" ? [] : [user.branchId]);

  const sales = await pool.query(`
    SELECT s.id, s.branch_id, b.name AS branch_name,
           u.username, u.name AS employee_name,
           s.total, s.created_at
    FROM sales s
    JOIN branches b ON b.id = s.branch_id
    JOIN users u ON u.id = s.user_id
    ${user.role === "admin" ? "" : "WHERE s.branch_id = $1"}
    ORDER BY s.created_at DESC
    LIMIT 100
  `, user.role === "admin" ? [] : [user.branchId]);

  let warehouseStock = [];

  if (user.role === "admin") {
    const result = await pool.query(`
      SELECT p.id AS product_id, p.name, w.quantity
      FROM warehouse_stock w
      JOIN products p ON p.id = w.product_id
      ORDER BY p.name
    `);

    warehouseStock = result.rows;
  }

  res.json({
    user,
    branches: user.role === "admin"
      ? branches.rows
      : branches.rows.filter(b => b.id === user.branchId),
    products: products.rows,
    warehouseStock,
    sales: sales.rows
  });
}));

app.post("/api/products", requireLogin, requireAdmin,
  asyncRoute(async (req, res) => {
    const name = String(req.body.name

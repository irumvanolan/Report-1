
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

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Banza winjire muri sisitemu." });
  }
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Uburenganzira ntibuhagije." });
  }
  next();
}
function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    name: user.name,
    role: user.role,
    branchId: user.branch_id || null
  };
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS branches (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE
    );
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      cost_price NUMERIC(14,2) NOT NULL DEFAULT 0,
      selling_price NUMERIC(14,2) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS stock (
      id SERIAL PRIMARY KEY,
      branch_id INTEGER NOT NULL REFERENCES branches(id),
      product_id INTEGER NOT NULL REFERENCES products(id),
      quantity INTEGER NOT NULL DEFAULT 0 CHECK (quantity >= 0),
      UNIQUE(branch_id, product_id)
    );
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'branch',
      branch_id INTEGER REFERENCES branches(id),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS transfers (
      id SERIAL PRIMARY KEY,
      product_id INTEGER NOT NULL REFERENCES products(id),
      from_branch INTEGER REFERENCES branches(id),
      to_branch INTEGER NOT NULL REFERENCES branches(id),
      quantity INTEGER NOT NULL CHECK (quantity > 0),
      user_id INTEGER REFERENCES users(id),
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
      user_id INTEGER REFERENCES users(id),
      details TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    INSERT INTO branches(name) VALUES ('Ishami 1'), ('Ishami 2')
    ON CONFLICT(name) DO NOTHING
  `);

  await pool.query(`
    INSERT INTO stock(branch_id, product_id, quantity)
    SELECT b.id, p.id, 0 FROM branches b CROSS JOIN products p
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

app.get("/api/health", (req, res) => {
  res.json({ ok: true, app: "Report 1" });
});

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
    if (err) return res.status(500).json({ error: "Ikibazo cya session." });

    req.session.user = publicUser(user);
    req.session.save(saveErr => {
      if (saveErr) {
        return res.status(500).json({ error: "Session ntiyabitswe." });
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
    ORDER BY p.id, s.branch_id
  `);

  const sales = await pool.query(`
    SELECT s.id, s.branch_id, b.name AS branch_name,
           u.username, u.name AS employee_name,
           s.total, s.created_at
    FROM sales s
    JOIN branches b ON b.id = s.branch_id
    JOIN users u ON u.id = s.user_id
    ${user.role === "admin" ? "" : "WHERE s.branch_id = $1"}
    ORDER BY s.created_at DESC LIMIT 100
  `, user.role === "admin" ? [] : [user.branchId]);

  res.json({
    user,
    branches: branches.rows,
    products: products.rows,
    sales: sales.rows
  });
}));

app.post("/api/products", requireLogin, requireAdmin, asyncRoute(async (req, res) => {
  const name = String(req.body.name || "").trim();
  const sellingPrice = Number(req.body.sellingPrice);
  const costPrice = Number(req.body.costPrice || 0);

  if (!name || !Number.isFinite(sellingPrice) || sellingPrice < 0 ||
      !Number.isFinite(costPrice) || costPrice < 0) {
    return res.status(400).json({ error: "Amakuru y'igicuruzwa si yo." });
  }

  const result = await pool.query(
    `INSERT INTO products(name, selling_price, cost_price)
     VALUES ($1, $2, $3) RETURNING *`,
    [name, sellingPrice, costPrice]
  );

  await pool.query(`
    INSERT INTO stock(branch_id, product_id, quantity)
    SELECT id, $1, 0 FROM branches ON CONFLICT DO NOTHING
  `, [result.rows[0].id]);

  res.status(201).json({ product: result.rows[0] });
}));

app.post("/api/transfer", requireLogin, requireAdmin, asyncRoute(async (req, res) => {
  const productId = Number(req.body.productId);
  const toBranch = Number(req.body.toBranch);
  const quantity = Number(req.body.quantity);

  if (!productId || !toBranch || !Number.isInteger(quantity) || quantity <= 0) {
    return res.status(400).json({ error: "Amakuru yo kohereza stock si yo." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const product = await client.query(
      "SELECT id FROM products WHERE id=$1",
      [productId]
    );
    const branch = await client.query(
      "SELECT id FROM branches WHERE id=$1",
      [toBranch]
    );

    if (!product.rowCount || !branch.rowCount) {
      throw Object.assign(new Error("Igicuruzwa cyangwa ishami ntibiboneka."), {status:404});
    }

    await client.query(`
      INSERT INTO stock(branch_id, product_id, quantity)
      VALUES ($1, $2, $3)
      ON CONFLICT(branch_id, product_id)
      DO UPDATE SET quantity = stock.quantity + EXCLUDED.quantity
    `, [toBranch, productId, quantity]);

    await client.query(`
      INSERT INTO transfers(product_id, to_branch, quantity, user_id)
      VALUES ($1, $2, $3, $4)
    `, [productId, toBranch, quantity, req.session.user.id]);

    await client.query(`
      INSERT INTO stock_movements(product_id, branch_id, movement_type, quantity, user_id, details)
      VALUES ($1, $2, 'transfer_in', $3, $4, 'Koherezwa stock ku ishami')
    `, [productId, toBranch, quantity, req.session.user.id]);

    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}));

app.post("/api/sale", requireLogin, asyncRoute(async (req, res) => {
  const user = req.session.user;
  const productId = Number(req.body.productId);
  const quantity = Number(req.body.quantity);
  const branchId = user.role === "admin" ? Number(req.body.branchId) : Number(user.branchId);

  if (!productId || !branchId || !Number.isInteger(quantity) || quantity <= 0) {
    return res.status(400).json({ error: "Amakuru y'igurisha si yo." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const stockResult = await client.query(`
      SELECT s.quantity, p.selling_price, p.name
      FROM stock s JOIN products p ON p.id=s.product_id
      WHERE s.product_id=$1 AND s.branch_id=$2
      FOR UPDATE
    `, [productId, branchId]);

    const stock = stockResult.rows[0];
    if (!stock || Number(stock.quantity) < quantity) {
      throw Object.assign(new Error("Stock ntihagije kuri iryo shami."), {status:400});
    }

    const total = Number(stock.selling_price) * quantity;
    const sale = await client.query(`
      INSERT INTO sales(branch_id, user_id, total)
      VALUES ($1, $2, $3) RETURNING id
    `, [branchId, user.id, total]);

    await client.query(`
      INSERT INTO sale_items(sale_id, product_id, quantity, unit_price, line_total)
      VALUES ($1, $2, $3, $4, $5)
    `, [sale.rows[0].id, productId, quantity, stock.selling_price, total]);

    await client.query(`
      UPDATE stock SET quantity=quantity-$1
      WHERE product_id=$2 AND branch_id=$3
    `, [quantity, productId, branchId]);

    await client.query(`
      INSERT INTO stock_movements(product_id, branch_id, movement_type, quantity, user_id, details)
      VALUES ($1, $2, 'sale', $3, $4, 'Igurisha')
    `, [productId, branchId, quantity, user.id]);

    await client.query("COMMIT");
    res.json({ ok: true, saleId: sale.rows[0].id, total });
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}));

app.get("/api/reports/sales", requireLogin, asyncRoute(async (req, res) => {
  const user = req.session.user;
  const result = await pool.query(`
    SELECT b.name AS branch_name, u.username,
           u.name AS employee_name, COUNT(s.id)::int AS sales_count,
           COALESCE(SUM(s.total), 0) AS total_sales
    FROM branches b
    LEFT JOIN sales s ON s.branch_id = b.id
    LEFT JOIN users u ON u.id = s.user_id
    ${user.role === "admin" ? "" : "WHERE b.id = $1"}
    GROUP BY b.id, b.name, u.id, u.username, u.name
    ORDER BY b.id
  `, user.role === "admin" ? [] : [user.branchId]);

  res.json({ reports: result.rows });
}));

app.get("/api/history", requireLogin, asyncRoute(async (req, res) => {
  const user = req.session.user;
  const result = await pool.query(`
    SELECT m.id, p.name AS product_name, b.name AS branch_name,
           m.movement_type, m.quantity, u.username,
           u.name AS employee_name, m.details, m.created_at
    FROM stock_movements m
    JOIN products p ON p.id = m.product_id
    JOIN branches b ON b.id = m.branch_id
    JOIN users u ON u.id = m.user_id
    ${user.role === "admin" ? "" : "WHERE m.branch_id = $1"}
    ORDER BY m.created_at DESC LIMIT 200
  `, user.role === "admin" ? [] : [user.branchId]);

  res.json({ history: result.rows });
}));

app.use(express.static(path.join(__dirname, "public")));

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ error: "API ntiboneka." });
  }
  res.status(404).send("Report 1: index.html ntirashyirwamo.");
});

app.use((err, req, res, next) => {
  console.error("Ikosa:", err);
  if (res.headersSent) return next(err);

  const status = err.status || (err.code === "23505" ? 409 : 500);
  res.status(status).json({
    error: status === 500
      ? "Ikibazo cya server. Reba logs za Render."
      : err.message
  });
});

async function start() {
  await initDB();
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Report 1 yatangiye kuri port ${PORT}`);
  });
}

start().catch(err => {
  console.error("Report 1 yananiwe gutangira:", err);
  process.exit(1);
});

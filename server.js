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
    return res.status(401).json({ error: "Banza winjire muri system." });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.user?.role !== "admin") {
    return res.status(403).json({ error: "Admin gusa yemerewe iki gikorwa." });
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
    branches: user.role === "admin"
      ? branches.rows
      : branches.rows.filter(b => b.id === user.branchId),
    products: products.rows,
    sales: sales.rows
  });
}));

app.post("/api/products", requireLogin, requireAdmin,
  asyncRoute(async (req, res) => {
    const name = String(req.body.name || "").trim();
    const sellingPrice = Number(req.body.sellingPrice);
    const costPrice = Number(req.body.costPrice ?? 0);

    if (!name || name.length > 150 ||
        !Number.isFinite(sellingPrice) || sellingPrice < 0 ||
        !Number.isFinite(costPrice) || costPrice < 0) {
      return res.status(400).json({ error: "Amakuru y'igicuruzwa si yo." });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const result = await client.query(
        `INSERT INTO products(name, selling_price, cost_price)
         VALUES ($1, $2, $3) RETURNING *`,
        [name, sellingPrice, costPrice]
      );

      await client.query(`
        INSERT INTO stock(branch_id, product_id, quantity)
        SELECT id, $1, 0 FROM branches
        ON CONFLICT DO NOTHING
      `, [result.rows[0].id]);

      await client.query("COMMIT");
      res.status(201).json({ product: result.rows[0] });
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  })
);

app.post("/api/transfer", requireLogin, requireAdmin,
  asyncRoute(async (req, res) => {
    const productId = Number(req.body.productId);
    const toBranch = Number(req.body.toBranch);
    const quantity = Number(req.body.quantity);

    if (!Number.isInteger(productId) || !Number.isInteger(toBranch) ||
        !Number.isInteger(quantity) || quantity <= 0) {
      return res.status(400).json({ error: "Amakuru yo kohereza si yo." });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const product = await client.query(
        "SELECT id FROM products WHERE id = $1", [productId]
      );
      const branch = await client.query(
        "SELECT id FROM branches WHERE id = $1", [toBranch]
      );

      if (!product.rowCount || !branch.rowCount) {
        throw Object.assign(
          new Error("Igicuruzwa cyangwa ishami ntibiboneka."),
          { status: 400 }
        );
      }

      await client.query(`
        UPDATE stock SET quantity = quantity + $1
        WHERE branch_id = $2 AND product_id = $3
      `, [quantity, toBranch, productId]);

      await client.query(`
        INSERT INTO transfers(product_id, to_branch, quantity, user_id)
        VALUES ($1, $2, $3, $4)
      `, [productId, toBranch, quantity, req.session.user.id]);

      await client.query(`
        INSERT INTO stock_movements
          (product_id, branch_id, movement_type, quantity, user_id, details)
        VALUES ($1, $2, 'transfer_in', $3, $4, 'Stock yoherejwe na admin')
      `, [productId, toBranch, quantity, req.session.user.id]);

      await client.query("COMMIT");
      res.json({ ok: true, message: "Stock yongewe ku ishami." });
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  })
);

app.post("/api/sale", requireLogin, asyncRoute(async (req, res) => {
  const user = req.session.user;
  const branchId = user.role === "admin"
    ? Number(req.body.branchId)
    : user.branchId;
  const items = req.body.items;

  if (!Number.isInteger(branchId) || !Array.isArray(items) ||
      items.length === 0 || items.length > 100) {
    return res.status(400).json({ error: "Amakuru y'igurisha si yo." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const branch = await client.query(
      "SELECT id FROM branches WHERE id = $1", [branchId]
    );
    if (!branch.rowCount) {
      throw Object.assign(new Error("Ishami ntiriboneka."), { status: 400 });
    }

    const sale = await client.query(
      `INSERT INTO sales(branch_id, user_id, total)
       VALUES ($1, $2, 0) RETURNING id`,
      [branchId, user.id]
    );

    let total = 0;

    for (const item of items) {
      const productId = Number(item.productId);
      const quantity = Number(item.quantity);

      if (!Number.isInteger(productId) ||
          !Number.isInteger(quantity) || quantity <= 0) {
        throw Object.assign(new Error("Umubare w'ibicuruzwa si wo."), {
          status: 400
        });
      }

      const product = await client.query(
        "SELECT id, selling_price FROM products WHERE id = $1",
        [productId]
      );
      if (!product.rowCount) {
        throw Object.assign(new Error("Igicuruzwa ntikiboneka."), {
          status: 400
        });
      }

      const updated = await client.query(`
        UPDATE stock SET quantity = quantity - $1
        WHERE branch_id = $2 AND product_id = $3 AND quantity >= $1
        RETURNING quantity
      `, [quantity, branchId, productId]);

      if (!updated.rowCount) {
        throw Object.assign(new Error("Stock ntihagije."), { status: 400 });
      }

      const price = Number(product.rows[0].selling_price);
      const lineTotal = Math.round(price * quantity * 100) / 100;
      total = Math.round((total + lineTotal) * 100) / 100;

      await client.query(`
        INSERT INTO sale_items
          (sale_id, product_id, quantity, unit_price, line_total)
        VALUES ($1, $2, $3, $4, $5)
      `, [sale.rows[0].id, productId, quantity, price, lineTotal]);

      await client.query(`
        INSERT INTO stock_movements
          (product_id, branch_id, movement_type, quantity, user_id, details)
        VALUES ($1, $2, 'sale', $3, $4, $5)
      `, [productId, branchId, -quantity, user.id,
          `Igurisha #${sale.rows[0].id}`]);
    }

    await client.query(
      "UPDATE sales SET total = $1 WHERE id = $2",
      [total, sale.rows[0].id]
    );

    await client.query("COMMIT");
    res.status(201).json({ ok: true, saleId: sale.rows[0].id, total });
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}));

app.post("/api/users", requireLogin, requireAdmin,
  asyncRoute(async (req, res) => {
    const username = String(req.body.username || "").trim();
    const name = String(req.body.name || "").trim();
    const password = String(req.body.password || "");
    const branchId = Number(req.body.branchId);

    if (!/^[a-zA-Z0-9_.-]{3,40}$/.test(username) ||
        !name || name.length > 100 || password.length < 12 ||
        !Number.isInteger(branchId)) {
      return res.status(400).json({
        error: "Reba izina, ishami n'ijambo ry'ibanga (inyuguti 12 nibura)."
      });
    }

    const branch = await pool.query(
      "SELECT id FROM branches WHERE id = $1", [branchId]
    );
    if (!branch.rowCount) {
      return res.status(400).json({ error: "Ishami ntiriboneka." });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(`
      INSERT INTO users(username, password_hash, name, role, branch_id)
      VALUES ($1, $2, $3, 'branch', $4)
      RETURNING id, username, name, role, branch_id
    `, [username, hash, name, branchId]);

    res.status(201).json({ user: publicUser(result.rows[0]) });
  })
);

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

// Urubuga ruzajya rutangwa muri public/index.html
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

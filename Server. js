require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const PgSession = require("connect-pg-simple")(session);

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET) {
  throw new Error("DATABASE_URL and SESSION_SECRET are required.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set("trust proxy", 1);

app.use(session({
  store: new PgSession({
    pool,
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(express.static("public"));

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      full_name VARCHAR(150) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      phone VARCHAR(30) NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      plan VARCHAR(100) NOT NULL,
      transaction_code VARCHAR(100) UNIQUE NOT NULL,
      status VARCHAR(20) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      success: false,
      message: "Please log in first."
    });
  }
  next();
}

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { fullName, email, phone, password } = req.body;

    if (!fullName || !email || !phone || !password) {
      return res.status(400).json({
        message: "All fields are required."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        message: "Password must have at least 8 characters."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );

    if (existing.rows.length) {
      return res.status(409).json({
        message: "Email already registered."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users
       (full_name, email, phone, password)
       VALUES ($1, $2, $3, $4)
       RETURNING id, full_name, email, phone`,
      [
        fullName.trim(),
        normalizedEmail,
        phone.trim(),
        hashedPassword
      ]
    );

    const user = result.rows[0];

    req.session.user = {
      id: user.id,
      fullName: user.full_name,
      email: user.email,
      phone: user.phone
    };

    res.status(201).json({
      success: true,
      message: "Registration successful.",
      user: req.session.user
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Registration failed."
    });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required."
      });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email.trim().toLowerCase()]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        message: "Incorrect email or password."
      });
    }

    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({
          message: "Could not create login session."
        });
      }

      req.session.user = {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        phone: user.phone
      };

      res.json({
        success: true,
        message: "Login successful.",
        user: req.session.user
      });
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Login failed."
    });
  }
});

// Current user
app.get("/api/me", requireLogin, (req, res) => {
  res.json({
    success: true,
    user: req.session.user
  });
});

// Logout
app.post("/api/logout", requireLogin, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        message: "Logout failed."
      });
    }

    res.clearCookie("connect.sid");

    res.json({
      success: true,
      message: "Logged out successfully."
    });
  });
});

// Submit subscription payment for verification
app.post("/api/payments", requireLogin, async (req, res) => {
  try {
    const { plan, transactionCode } = req.body;

    if (!plan || !transactionCode) {
      return res.status(400).json({
        message: "Plan and transaction code are required."
      });
    }

    const result = await pool.query(
      `INSERT INTO payments
       (user_id, plan, transaction_code)
       VALUES ($1, $2, $3)
       RETURNING id, plan, status, transaction_code`,
      [
        req.session.user.id,
        plan.trim(),
        transactionCode.trim().toUpperCase()
      ]
    );

    res.status(201).json({
      success: true,
      message: "Payment submitted for verification.",
      payment: result.rows[0]
    });

  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        message: "This transaction code has already been submitted."
      });
    }

    console.error(error);

    res.status(500).json({
      message: "Payment submission failed."
    });
  }
});

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "BILLPATRON is running."
  });
});

// Start server
initializeDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`BILLPATRON running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Database initialization failed:", error);
    process.exit(1);
  });

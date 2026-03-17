import express from "express";
import { createServer } from "http";
import { Server as SocketServer } from "socket.io";
import mysql from "mysql2/promise";
import mysql2Cb from "mysql2";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import session from "express-session";
import nodemailer from "nodemailer";
import PDFDocument from "pdfkit";
import fs from "fs";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import Razorpay from "razorpay";
import crypto from "crypto";
import { VertexAI } from "@google-cloud/vertexai";
import MySQLStore from "express-mysql-session";
import dotenv from "dotenv";
import { TEMPLATES, getTemplateById } from "./config/templates-config.js";
import QRCode from "qrcode";
import { getFieldsForTemplate, isPhotoTemplate } from "./config/template-fields.js";
import adminRouter from "./routes/admin.js";
import { removeBackgroundFromImageBase64 } from "remove.bg";
let _removeBackground = null;
async function getRemoveBg() {
  if (!_removeBackground) {
    const mod = await import("@imgly/background-removal-node");
    _removeBackground = mod.removeBackground;
  }
  return _removeBackground;
}

const MysqlSession = MySQLStore(session);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

// ----- Razorpay setup (lazy — re-reads process.env on each call) -----
function getRazorpay() {
  return new Razorpay({
    key_id:     process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
  });
}
// ----- Gemini (Vertex AI) setup -----
let geminiModel = null;
try {
  const vertexOpts = {
    project:  process.env.GCP_PROJECT_ID,
    location: "us-central1",
  };

  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    // Production (Render): credentials stored as a JSON string in env var.
    // Delete GOOGLE_APPLICATION_CREDENTIALS first — otherwise the SDK ignores
    // the explicit credentials and tries to read the (missing) file instead.
    delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
    vertexOpts.googleAuthOptions = {
      credentials: JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON),
      scopes: ["https://www.googleapis.com/auth/cloud-platform"],
    };
  } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  } else {
  }

  const vertexAI = new VertexAI(vertexOpts);
  geminiModel = vertexAI.getGenerativeModel({ model: "gemini-2.0-flash" });
} catch (err) {
}
// Optional: helpful warning in dev
if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
}

const app = express();
// ---------- MySQL ----------
const pool = mysql.createPool({
  uri: process.env.DATABASE_URL,
  waitForConnections: true,
  connectionLimit: 10,
  decimalNumbers: true,
});

// Callback-based pool for express-mysql-session (requires non-promise pool)
const sessionPool = mysql2Cb.createPool(process.env.DATABASE_URL);

const db = {
  async query(sql, params) {
    const [result] = await pool.query(sql, params || []);
    if (Array.isArray(result)) {
      return { rows: result, rowCount: result.length };
    }
    return { rows: [], rowCount: result.affectedRows, insertId: result.insertId };
  }
};

async function initDb() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS service_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        service_type VARCHAR(100) NOT NULL,
        details TEXT,
        status VARCHAR(50) DEFAULT 'new',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await db.query(`
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    password TEXT,
    google_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

await db.query(`
  CREATE TABLE IF NOT EXISTS user_profiles (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    full_name TEXT,
    role_title TEXT,
    location TEXT,
    phone TEXT,
    email TEXT,
    summary TEXT,
    experience TEXT,
    education TEXT,
    languages TEXT,
    skills TEXT,
    profile_image_url MEDIUMTEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

await db.query(`
  CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    otp_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

    /* resumes main table */
    await db.query(`
      CREATE TABLE IF NOT EXISTS resumes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL DEFAULT 'Untitled Resume',
        template VARCHAR(100) NOT NULL DEFAULT 'modern-1',
        data JSON NOT NULL,
        experience_level VARCHAR(50) DEFAULT 'experienced',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    /* experience_level column (safe to run on every startup — for older DBs) */
    await db.query(`ALTER TABLE resumes ADD COLUMN experience_level VARCHAR(50) DEFAULT 'experienced'`).catch(() => {});

    /* download/print events (for stats) */
    await db.query(`
      CREATE TABLE IF NOT EXISTS resume_events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        resume_id INTEGER REFERENCES resumes(id) ON DELETE CASCADE,
        kind VARCHAR(50) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    /* payment history (Razorpay) */
    await db.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        resume_id INTEGER REFERENCES resumes(id) ON DELETE SET NULL,
        purpose VARCHAR(50),
        amount INTEGER,
        currency VARCHAR(10),
        razorpay_order_id TEXT,
        razorpay_payment_id TEXT,
        razorpay_signature TEXT,
        status VARCHAR(30) DEFAULT 'captured',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    /* ── Admin: role column on users ── */
    await db.query(`ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'`).catch(() => {});
    await db.query(`ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT true`).catch(() => {});

    /* ── Activity logs table ── */
    await db.query(`
      CREATE TABLE IF NOT EXISTS activity_logs (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
        action_type  VARCHAR(50) NOT NULL,
        route        VARCHAR(255),
        metadata     JSON,
        ip_address   VARCHAR(45),
        created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await db.query(`CREATE INDEX idx_activity_logs_created ON activity_logs(created_at)`).catch(() => {});
    await db.query(`CREATE INDEX idx_activity_logs_user ON activity_logs(user_id)`).catch(() => {});
    await db.query(`ALTER TABLE service_requests ADD COLUMN user_id INTEGER`).catch(() => {});

    /* ── Request chat messages ── */
    await db.query(`
      CREATE TABLE IF NOT EXISTS request_messages (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        request_id  INTEGER NOT NULL REFERENCES service_requests(id) ON DELETE CASCADE,
        sender_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
        sender_role VARCHAR(20) NOT NULL DEFAULT 'user',
        message     TEXT NOT NULL,
        is_read     BOOLEAN NOT NULL DEFAULT false,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await db.query(`CREATE INDEX idx_req_msg_request ON request_messages(request_id)`).catch(() => {});
    await db.query(`ALTER TABLE service_requests ADD COLUMN guest_token VARCHAR(64)`).catch(() => {});

    /* ── Admin settings (key-value store for prices, etc.) ── */
    await db.query(`
      CREATE TABLE IF NOT EXISTS admin_settings (
        \`key\`      VARCHAR(255) PRIMARY KEY,
        value      MEDIUMTEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await db.query(`
      INSERT IGNORE INTO admin_settings (\`key\`, value) VALUES
        ('price_fresher',      '100'),
        ('price_experienced',  '100'),
        ('price_developer',    '500'),
        ('price_ats-friendly', '500')
    `);
    await db.query(`INSERT IGNORE INTO admin_settings (\`key\`, value) VALUES ('ads_enabled', 'true')`);
    await db.query(`INSERT IGNORE INTO admin_settings (\`key\`, value) VALUES ('google_translate_enabled', 'false')`);

    // ── Homepage editable content defaults ───────────────────────────────────
    const homepageDefaults = [
      ['homepage_hero', JSON.stringify({
        tag:       "AI-Powered Resume Studio",
        headline:  "Build a job-ready resume in minutes, not hours.",
        subtitle:  "SmrAI-Studio helps you create clean, modern resumes with AI guidance, professional layouts, and instant download as PDF or JPG.",
        trustText: "No design skills needed · 8 professional templates · AI-powered content",
      })],
      ['homepage_services', JSON.stringify({
        title:    "What you can do with SmrAI-Studio",
        subtitle: "From your first resume to your next promotion, SmrAI-Studio grows with your career.",
        cards: [
          { title: "Resume Making",     description: "Generate a clean, ATS-friendly resume with professional wording and layout in minutes.",                                                   link: "/resume-templates",     bgClass: "resume-bg",    imageUrl: "" },
          { title: "AI Cover Letters",  description: "Tailored cover letters for each job description, matching your skills and experience.",                                                   link: "",                      bgClass: "cover-bg",     imageUrl: "" },
          { title: "Profile & Portfolio", description: "Keep your details saved, update once, and export resumes or profiles whenever you need.",                                               link: "",                      bgClass: "portfolio-bg", imageUrl: "" },
          { title: "Applications (A4)", description: "Write formal applications — sick leave, resignation, appreciation and more — with AI guidance and voice input.",                         link: "/application-builder",  bgClass: "app-bg",       imageUrl: "" },
          { title: "SmrPhoto Editor",   description: "Edit, enhance and personalise your photos with powerful AI tools — crop, filters, adjustments and more in one click.",        link: "/photo-editor",       bgClass: "photo-bg",     imageUrl: "" },
          { title: "Background Remover", description: "Remove image backgrounds instantly with AI — clean, precise cutouts in seconds. Perfect for resumes, portfolios, and more.", link: "/background-remover", bgClass: "bg-remover-bg", imageUrl: "" },
        ],
      })],
      ['bgremover_backgrounds', JSON.stringify([])],
      ['bgremover_provider', 'removebg'],
      ['homepage_features', JSON.stringify({
        title:    "Our Main Features",
        subtitle: "Start building your resume today and land your next role faster.",
        cards: [
          { icon: "📄", color: "orange", title: "Proven Templates",      description: "Layouts designed to pass ATS scans and impress hiring managers." },
          { icon: "🎨", color: "blue",   title: "Modern & Clean Design", description: "Balanced typography, spacing, and structure—no messy Word docs." },
          { icon: "⚙️", color: "red",    title: "AI Writing Assistance", description: "SmrAI helps with bullet points, summaries, and role descriptions." },
          { icon: "⚡", color: "green",  title: "1-Click Download",      description: "Export as high quality PDF or JPG, ready to send anywhere." },
          { icon: "🔔", color: "yellow", title: "Profile Saved",         description: "Your details stay saved—update once, reuse in multiple templates." },
          { icon: "🌐", color: "purple", title: "Accessible Anywhere",   description: "Works from any device with a browser—no installs needed." },
        ],
      })],
      ['homepage_testimonials', JSON.stringify({
        title:    "Your Success, Our Inspiration",
        subtitle: "Don't just take it from us. Here's what users say about SmrAI-Studio.",
        cards: [
          { avatar: "https://i.pravatar.cc/56?img=11", name: "Ajay Mehra",       role: "Full Stack Developer", text: "SmrAI-Studio made my resume look 10x more professional. I updated everything in under an hour and started getting callbacks within a week." },
          { avatar: "https://i.pravatar.cc/56?img=47", name: "Suchi Gupta",      role: "HR Manager",          text: "Clean design and very easy to use. I update my resume for different roles and download new versions instantly. Huge time saver." },
          { avatar: "https://i.pravatar.cc/56?img=68", name: "Puneet Srivastava",role: "Sales Manager",       text: "The AI suggestions for bullet points helped me describe my experience clearly and confidently. Highly recommended." },
        ],
      })],
    ];
    for (const [key, value] of homepageDefaults) {
      await db.query(
        `INSERT IGNORE INTO admin_settings (\`key\`, value) VALUES (?,?)`,
        [key, value]
      );
    }

    /* ── Admin Template Builder: dynamic templates created via admin panel ── */
    await db.query(`
      CREATE TABLE IF NOT EXISTS admin_templates (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        slug         VARCHAR(100) UNIQUE NOT NULL,
        title        VARCHAR(255) NOT NULL,
        description  TEXT,
        category     VARCHAR(50) NOT NULL DEFAULT 'experienced',
        badge        VARCHAR(100) DEFAULT 'New',
        layout_type  VARCHAR(50) DEFAULT 'two-column-left',
        color_scheme JSON,
        thumbnail_url TEXT,
        adobe_design_id TEXT,
        is_paid      BOOLEAN DEFAULT true,
        price_inr    INTEGER DEFAULT 49,
        is_published BOOLEAN DEFAULT false,
        sort_order   INTEGER DEFAULT 0,
        created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at   TIMESTAMP DEFAULT NOW(),
        updated_at   TIMESTAMP DEFAULT NOW()
      )
    `).catch(() => {});

    await db.query(`
      CREATE TABLE IF NOT EXISTS admin_template_sections (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        template_id INTEGER REFERENCES admin_templates(id) ON DELETE CASCADE,
        section_key VARCHAR(100) NOT NULL,
        is_enabled  BOOLEAN DEFAULT true,
        sort_order  INTEGER DEFAULT 0,
        UNIQUE(template_id, section_key)
      )
    `).catch(() => {});

    // Upgrade columns to MEDIUMTEXT for base64 storage
    await db.query(`ALTER TABLE user_profiles MODIFY COLUMN profile_image_url MEDIUMTEXT`).catch(() => {});
    await db.query(`ALTER TABLE admin_settings MODIFY COLUMN value MEDIUMTEXT NOT NULL`).catch(() => {});

    // Idempotent column additions — safe to run every startup
    await db.query(`ALTER TABLE admin_template_sections ADD COLUMN placement VARCHAR(20) DEFAULT 'auto'`).catch(() => {});
    await db.query(`ALTER TABLE admin_template_sections ADD COLUMN display_type VARCHAR(30) DEFAULT 'bullets'`).catch(() => {});
    await db.query(`ALTER TABLE admin_template_sections ADD COLUMN label_override VARCHAR(150)`).catch(() => {});

    await db.query(`ALTER TABLE admin_settings ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`).catch(() => {});
    await db.query(`ALTER TABLE admin_templates ADD COLUMN design_settings JSON`).catch(() => {});
    await db.query(`ALTER TABLE admin_templates ADD COLUMN background_image_url TEXT`).catch(() => {});
    await db.query(`ALTER TABLE template_overrides ADD COLUMN background_image_url TEXT`).catch(() => {});

    /* ── Static template overrides: admin edits to hardcoded templates ── */
    await db.query(`
      CREATE TABLE IF NOT EXISTS template_overrides (
        template_id       VARCHAR(100) PRIMARY KEY,
        title             VARCHAR(255),
        description       TEXT,
        preview_image_url TEXT,
        is_available      BOOLEAN,
        badge             VARCHAR(100),
        updated_at        TIMESTAMP DEFAULT NOW()
      )
    `).catch(() => {});

    await db.query(`
      CREATE TABLE IF NOT EXISTS ads (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        slot       VARCHAR(20) NOT NULL CHECK (slot IN ('sidebar','footer')),
        title      VARCHAR(200),
        image_url  TEXT,
        link_url   TEXT NOT NULL,
        is_active  BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `).catch(() => {});

    await db.query(`
      CREATE TABLE IF NOT EXISTS coupons (
        id               INT AUTO_INCREMENT PRIMARY KEY,
        code             VARCHAR(50) UNIQUE NOT NULL,
        description      VARCHAR(200),
        discount_type    VARCHAR(10) NOT NULL CHECK (discount_type IN ('percent','fixed')),
        discount_value   NUMERIC(10,2) NOT NULL,
        min_amount       NUMERIC(10,2) DEFAULT 0,
        max_uses         INTEGER DEFAULT 0,
        uses_count       INTEGER DEFAULT 0,
        first_time_only  BOOLEAN DEFAULT false,
        is_active        BOOLEAN DEFAULT true,
        expires_at       TIMESTAMP NULL,
        created_at       TIMESTAMP DEFAULT NOW()
      )
    `).catch(() => {});

    await db.query(`ALTER TABLE payments ADD COLUMN coupon_code TEXT`).catch(() => {});

    // ── Referral system columns ──────────────────────────────────────────────
    await db.query(`ALTER TABLE users ADD COLUMN referral_code VARCHAR(20) UNIQUE`).catch(() => {});
    await db.query(`ALTER TABLE users ADD COLUMN referred_by INTEGER`).catch(() => {});
    await db.query(`ALTER TABLE users ADD COLUMN wallet_balance DECIMAL(10,2) NOT NULL DEFAULT 0`).catch(() => {});
    await db.query(`ALTER TABLE payments ADD COLUMN referral_reward_issued BOOLEAN NOT NULL DEFAULT false`).catch(() => {});

    // Backfill referral codes for existing users who don't have one
    const noCodeUsers = await db.query("SELECT id, name FROM users WHERE referral_code IS NULL").catch(() => ({ rows: [] }));
    for (const u of noCodeUsers.rows) {
      let code, tries = 0;
      do {
        code = generateReferralCode(u.name, u.id, tries++);
      } while (tries < 5);
      await db.query("UPDATE users SET referral_code=? WHERE id=? AND referral_code IS NULL", [code, u.id]).catch(() => {});
    }

    // ── Wallet transactions log ───────────────────────────────────────────────
    await db.query(`
      CREATE TABLE IF NOT EXISTS wallet_transactions (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        user_id    INT NOT NULL,
        amount     DECIMAL(10,2) NOT NULL,
        type       ENUM('credit','debit') NOT NULL,
        reason     VARCHAR(100) NOT NULL,
        ref_id     INT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX (user_id)
      )
    `).catch(() => {});

    // ── Investor system ───────────────────────────────────────────────────────
    await db.query(`ALTER TABLE users ADD COLUMN investor_approved BOOLEAN NOT NULL DEFAULT false`).catch(() => {});
    await db.query(`
      CREATE TABLE IF NOT EXISTS investor_requests (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        status     VARCHAR(20) NOT NULL DEFAULT 'pending',
        admin_note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id)
      )
    `).catch(() => {});
    await db.query(`ALTER TABLE investor_requests ADD COLUMN desired_amount NUMERIC(12,2)`).catch(() => {});
    await db.query(`ALTER TABLE investor_requests ADD COLUMN desired_equity NUMERIC(5,2)`).catch(() => {});
    await db.query(`ALTER TABLE investor_requests ADD COLUMN phone VARCHAR(20)`).catch(() => {});
    await db.query(`
      CREATE TABLE IF NOT EXISTS subadmin_permissions (
        id       INT AUTO_INCREMENT PRIMARY KEY,
        user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        section  VARCHAR(50) NOT NULL,
        level    VARCHAR(10) NOT NULL DEFAULT 'none',
        UNIQUE(user_id, section)
      )
    `).catch(() => {});
    await db.query(`
      CREATE TABLE IF NOT EXISTS investments (
        id                INT AUTO_INCREMENT PRIMARY KEY,
        user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        amount            NUMERIC(12,2) NOT NULL,
        equity_percent    NUMERIC(5,2) NOT NULL,
        valuation         NUMERIC(14,2) NOT NULL,
        payment_id        VARCHAR(255) NOT NULL,
        razorpay_order_id VARCHAR(255),
        created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(payment_id)
      )
    `).catch(() => {});
    // Seed default investment config
    await db.query(`
      INSERT IGNORE INTO admin_settings (\`key\`, value) VALUES
        ('investment_amount', '50000'),
        ('investment_equity', '40'),
        ('investment_valuation', '125000'),
        ('company_name', 'SmrAI Studio')
    `).catch(() => {});

    // Load env overrides from admin_settings (env_* keys)
    try {
      const envRows = await db.query("SELECT `key`, value FROM admin_settings WHERE `key` LIKE 'env_%'");
      for (const row of envRows.rows) {
        const envKey = row.key.replace(/^env_/, '').toUpperCase();
        if (row.value) process.env[envKey] = row.value;
      }
    } catch (_) {}

  } catch (err) {
    console.error('[initDb] FAILED:', err.message);
  }
}

/* 🔴 WEBHOOK MUST COME FIRST 🔴 */
app.post(
  "/webhook/razorpay",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const signature = req.headers["x-razorpay-signature"];
      const secret = process.env.RAZORPAY_WEBHOOK_SECRET;

      if (!signature || !secret) {
        return res.status(400).send("Webhook secret/signature missing");
      }

      const expectedSignature = crypto
        .createHmac("sha256", secret)
        .update(req.body)
        .digest("hex");

      if (expectedSignature !== signature) {
        return res.status(400).send("Invalid signature");
      }

      const event = JSON.parse(req.body.toString());
      if (event.event === "payment.captured") {
        const payment = event.payload.payment.entity;
        await db.query(
          `
          INSERT INTO payments (razorpay_payment_id, status, amount, currency)
          VALUES (?, 'captured', ?, ?)
          ON DUPLICATE KEY UPDATE status = 'captured'
          `,
          [payment.id, payment.amount, payment.currency]
        );

      }

      if (event.event === "payment.failed") {
        const payment = event.payload.payment.entity;

        await db.query(
          `
          INSERT INTO payments (razorpay_payment_id, status, amount, currency)
          VALUES (?, 'failed', ?, ?)
          ON DUPLICATE KEY UPDATE status = 'failed'
          `,
          [payment.id, payment.amount, payment.currency]
        );
      }

      return res.json({ received: true });
    } catch (err) {
      return res.status(500).send("Webhook error");
    }
  }
);


(async () => {
  await initDb();
})();

/* ✅ THEN body parsers */
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.json({ limit: "10mb" }));

// Normalize double-slash URLs (e.g. // → /) to avoid OG canonical mismatches
app.use((req, res, next) => {
  if (req.url.startsWith("//")) {
    return res.redirect(301, req.url.replace(/^\/+/, "/"));
  }
  next();
});

const port = process.env.PORT || 3000;
const saltRounds = 10;

// Static files
app.use(express.static(path.join(__dirname, "public")));
app.use((req, res, next) => { res.locals.currentPath = req.path; next(); });
const uploadDir = path.join(__dirname, "public", "uploads");

// Create "public/uploads" if it doesn't exist
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || ".jpg";
    const userId = req.user?.id || "guest";
    cb(null, `user-${userId}-${Date.now()}${ext}`);
  },
});

const upload = multer({ storage });

// ---------- View Engine & Static ----------
app.set("view engine", "ejs");
app.set("views", "views");

// ---------- Session & Passport ----------
const isProd = process.env.NODE_ENV === "production";

// Trust Render's proxy so Express sees the correct protocol (HTTPS) and
// allows secure cookies to be set. Harmless in local dev.
app.set("trust proxy", 1);

const sessionMiddleware = session({
  store: new MysqlSession({}, sessionPool),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    // Dev  (NODE_ENV=development): HTTP localhost → secure must be false
    // Prod (NODE_ENV=production):  HTTPS Render  → secure must be true
    secure: isProd,
    // "none" lets Android WebView & OAuth send cookies cross-context (requires secure:true)
    // "lax"  is the safe browser default and works fine on localhost
    sameSite: isProd ? "none" : "lax",
    maxAge: 1000 * 60 * 60 * 24 * 7,
  },
});
app.use(sessionMiddleware);

app.use(passport.initialize());
app.use(passport.session());

// ---------- Passport Local Strategy ----------
passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = ?", [
          email,
        ]);

        if (result.rows.length === 0) {
          return done(null, false, { message: "No user with that email" });
        }

        const user = result.rows[0];

        if (!user.password) {
          return done(null, false, { message: "Use Google login for this account" });
        }

        const match = await bcrypt.compare(password, user.password);

        if (!match) {
          return done(null, false, { message: "Incorrect password" });
        }

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// ---------- Passport Google Strategy (Scaffold) ----------
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || "",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
      callbackURL: "/auth/google/callback",
      passReqToCallback: true,
    },
    async (request, accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.email;
        const googleId = profile.id;
        const name = profile.displayName;

        let result = await db.query("SELECT * FROM users WHERE google_id = ?", [
          googleId,
        ]);

        if (result.rows.length === 0) {
          const insertResult = await db.query(
            "INSERT INTO users (email, google_id, name) VALUES (?, ?, ?)",
            [email, googleId, name]
          );
          result = await db.query("SELECT * FROM users WHERE id = ?", [insertResult.insertId]);
        }

        const user = result.rows[0];
        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

// ---------- Serialize / Deserialize ----------
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = ?", [id]);
    // Pass false (not undefined) when user not found — Passport clears the stale
    // session cookie silently instead of logging "Failed to deserialize user".
    done(null, result.rows[0] || false);
  } catch (err) {
    done(err, null);
  }
});

function getTransporter() {
  return nodemailer.createTransport({
    host:   process.env.EMAIL_HOST,
    port:   process.env.EMAIL_PORT,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
}

function generateOTP() {
  // 6-digit numeric OTP
  return Math.floor(100000 + Math.random() * 900000).toString();
}

app.use(async (req, res, next) => {
  res.locals.currentUser = req.user || null;
  res.locals.userProfile = null;

  if (req.user) {
    try {
      const profileResult = await db.query(
        "SELECT * FROM user_profiles WHERE user_id = ?",
        [req.user.id]
      );
      if (profileResult.rows.length > 0) {
        res.locals.userProfile = profileResult.rows[0];
      }
    } catch (err) {
    }
  }

  // Active ads for ad slots + master on/off + tracking scripts
  try {
    const [sbAd, ftAd, aeRow, trackingRows] = await Promise.all([
      db.query("SELECT * FROM ads WHERE slot='sidebar' AND is_active=true ORDER BY id DESC LIMIT 1"),
      db.query("SELECT * FROM ads WHERE slot='footer'  AND is_active=true ORDER BY id DESC LIMIT 1"),
      db.query("SELECT value FROM admin_settings WHERE `key`='ads_enabled'"),
      db.query("SELECT `key`, value FROM admin_settings WHERE `key` IN ('adsense_publisher_id', 'facebook_pixel_id', 'homepage_ad_slot', 'footer_ad_slot', 'google_translate_enabled')"),
    ]);
    res.locals.sidebarAd  = sbAd.rows[0] || null;
    res.locals.footerAd   = ftAd.rows[0] || null;
    res.locals.adsEnabled = (aeRow.rows[0]?.value ?? 'true') === 'true';
    const tm = {};
    for (const r of trackingRows.rows) tm[r.key] = r.value;
    res.locals.adsensePublisherId = tm['adsense_publisher_id'] || null;
    res.locals.facebookPixelId    = tm['facebook_pixel_id']    || null;
    res.locals.homepageAdSlot       = tm['homepage_ad_slot']          || null;
    res.locals.footerAdSlot         = tm['footer_ad_slot']            || null;
    res.locals.googleTranslateEnabled = tm['google_translate_enabled'] === 'true';
  } catch (_) {
    res.locals.sidebarAd = null; res.locals.footerAd = null; res.locals.adsEnabled = true;
    res.locals.adsensePublisherId = null; res.locals.facebookPixelId = null;
    res.locals.homepageAdSlot = null; res.locals.footerAdSlot = null;
    res.locals.googleTranslateEnabled = false;
  }

  next();
});

// ---------- Routes ----------

// ── My service requests — list and delete ────────────────────────────────────
app.get("/api/my-requests", ensureAuthenticated, async (req, res) => {
  try {
    const rows = await db.query(
      `SELECT id, service_type, details, status, created_at
       FROM service_requests
       WHERE user_id = ?
       ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json({ success: true, requests: rows.rows });
  } catch (_) {
    res.json({ success: false, requests: [] });
  }
});

app.delete("/api/my-request/:id", ensureAuthenticated, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (!id) return res.status(400).json({ success: false });
    // WHERE user_id = req.user.id ensures users can only delete their own requests
    const result = await db.query(
      "DELETE FROM service_requests WHERE id = ? AND user_id = ?",
      [id, req.user.id]
    );
    res.json({ success: result.rowCount > 0 });
  } catch (_) {
    res.status(500).json({ success: false });
  }
});

// ── Public stats — safe counts shown on home page & dashboard ────────────────
app.get("/api/public/stats", async (req, res) => {
  try {
    const [users, resumes, downloads] = await Promise.all([
      db.query("SELECT COUNT(*) AS count FROM users"),
      db.query("SELECT COUNT(*) AS count FROM resumes"),
      db.query("SELECT COUNT(*) AS count FROM resume_events WHERE kind = 'download'"),
    ]);
    res.json({
      users:     users.rows[0].count,
      resumes:   resumes.rows[0].count,
      downloads: downloads.rows[0].count,
    });
  } catch (_) {
    res.json({ users: 0, resumes: 0, downloads: 0 });
  }
});

// Home: your AI services landing page
app.get("/", async (_req, res) => {
  try {
    const rows = (await db.query(
      `SELECT \`key\`, value FROM admin_settings WHERE \`key\` IN ('homepage_hero','homepage_services','homepage_features','homepage_testimonials')`
    )).rows;
    const map = Object.fromEntries(rows.map(r => [r.key, JSON.parse(r.value)]));
    res.render("home", {
      hp_hero:         map.homepage_hero         || {},
      hp_services:     map.homepage_services     || {},
      hp_features:     map.homepage_features     || {},
      hp_testimonials: map.homepage_testimonials || {},
    });
  } catch (err) {
    res.render("home", { hp_hero:{}, hp_services:{}, hp_features:{}, hp_testimonials:{} });
  }
});

// Register
app.get("/register", async (req, res) => {
  const refCode = req.query.ref || '';
  const baseUrl = await getSiteUrl();
  let ogTitle, ogDescription, ogUrl, ogImage;
  ogImage = `${baseUrl}/images/refer.png`;
  if (refCode) {
    try {
      const row = await db.query(
        "SELECT name FROM users WHERE referral_code=? AND is_active=true",
        [refCode.trim().toUpperCase()]
      );
      const firstName = row.rows[0]?.name?.split(' ')[0] || 'Someone';
      ogTitle       = `${firstName} invites you to SmrAI Studio`;
      ogDescription = `Use code ${refCode.toUpperCase()} to get 30% off your first resume download! 🎉`;
      ogUrl         = `${baseUrl}/register?ref=${refCode.toUpperCase()}`;
    } catch (_) {}
  }
  res.render("register", { refCode, ogTitle, ogDescription, ogUrl, ogImage });
});

app.post("/register", async (req, res) => {
  const { name, email, password, referralCode } = req.body;

  try {
    const check = await db.query("SELECT * FROM users WHERE email = ?", [email]);

    if (check.rows.length > 0) {
      return res.render("already-registered");
    }
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const insertResult = await db.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword]
    );
    const userRow = await db.query("SELECT * FROM users WHERE id = ?", [insertResult.insertId]);

    const user = userRow.rows[0];

    // Generate unique referral code for new user
    let newCode, tries = 0;
    do {
      newCode = generateReferralCode(name, user.id, tries++);
      const conflict = await db.query("SELECT id FROM users WHERE referral_code=?", [newCode]);
      if (!conflict.rows.length) break;
    } while (tries < 10);
    await db.query("UPDATE users SET referral_code=? WHERE id=?", [newCode, user.id]).catch(() => {});

    // Link referrer if a valid referral code was provided
    if (referralCode && referralCode.trim()) {
      const upper = referralCode.trim().toUpperCase();
      const refUser = await db.query(
        "SELECT id FROM users WHERE referral_code=? AND is_active=true AND id<>?",
        [upper, user.id]
      );
      if (refUser.rows.length) {
        await db.query("UPDATE users SET referred_by=? WHERE id=?", [refUser.rows[0].id, user.id]).catch(() => {});
      }
    }

    req.login(user, (err) => {
      if (err) return res.redirect("/login");
      res.redirect("/dashboard");
    });
  } catch (err) {
    res.send("Error while registering");
  }
});

// Login
app.get("/login", (req, res) => {
  if (req.query.returnTo) {
    req.session.returnTo = req.query.returnTo;
  }
  res.render("login", { error: null });
});

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return next(err);
    }

    if (!user) {
      // Authentication failed – show message
      return res.render("login", { error: info?.message || "Login failed" });
    }

    // Read returnTo BEFORE req.logIn — Passport regenerates the session
    // on login (session fixation protection), wiping req.session data.
    const redirectTo = req.session.returnTo || "/dashboard";

    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      logActivity({ userId: user.id, actionType: "login", ip: req.ip });
      return res.redirect(redirectTo);
    });
  })(req, res, next);
});

// Forget Password
app.get("/forgot-password", (req, res) => {
  res.render("forgot-password", { message: null, error: null });
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = ?", [email]);

    if (result.rows.length === 0) {
      // For security, we don't say "no such email"
      return res.render("forgot-password", {
        message: "If an account exists with this email, an OTP has been sent.",
        error: null,
      });
    }

    const user = result.rows[0];
    const otp = generateOTP();
    const otpHash = await bcrypt.hash(otp, saltRounds);

    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 min from now

    await db.query(
      "INSERT INTO password_reset_tokens (user_id, otp_hash, expires_at) VALUES (?, ?, ?)",
      [user.id, otpHash, expiresAt]
    );

    // Send OTP email
    await getTransporter().sendMail({
      from: `"SmrAI-Studio" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your SmrAI-Studio Password Reset OTP",
      text: `Your OTP for resetting your SmrAI-Studio password is: ${otp}. It is valid for 15 minutes.`,
    });
    return res.redirect(`/reset-password?email=${encodeURIComponent(email)}`);
    // return res.render("forgot-password", {
    //   message: "If an account exists with this email, an OTP has been sent.",
    //   error: null,
    // });
  } catch (err) {
    return res.render("forgot-password", {
      message: null,
      error: "Something went wrong. Please try again.",
    });
  }
});

app.get("/reset-password", (req, res) => {
  const emailFromQuery = req.query.email || "";
  res.render("reset-password", {
    error: null,
    message: null,
    emailPrefill: emailFromQuery,
  });
});


app.post("/reset-password", async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const userResult = await db.query("SELECT * FROM users WHERE email = ?", [email]);

    if (userResult.rows.length === 0) {
      return res.render("reset-password", {
        error: "Invalid email or OTP.",
        message: null,
        emailPrefill: email,
      });
    }

    const user = userResult.rows[0];

    // Get latest unused token for this user
    const tokenResult = await db.query(
      `SELECT * FROM password_reset_tokens
       WHERE user_id = ? AND used = FALSE
       ORDER BY created_at DESC
       LIMIT 1`,
      [user.id]
    );

    if (tokenResult.rows.length === 0) {
      return res.render("reset-password", {
        error: "No valid OTP found. Please request a new one.",
        message: null,
        emailPrefill: email,
      });
    }

    const token = tokenResult.rows[0];

    const now = new Date();
    if (now > token.expires_at) {
      return res.render("reset-password", {
        error: "OTP has expired. Please request a new one.",
        message: null,
        emailPrefill: email,
      });
    }

    const otpMatch = await bcrypt.compare(otp, token.otp_hash);
    if (!otpMatch) {
      return res.render("reset-password", {
        error: "Incorrect OTP. Please try again.",
        message: null,
        emailPrefill: email,
      });
    }

    // OTP ok → update password & mark token used
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    await db.query("UPDATE users SET password = ? WHERE id = ?", [
      hashedPassword,
      user.id,
    ]);

    await db.query("UPDATE password_reset_tokens SET used = TRUE WHERE id = ?", [
      token.id,
    ]);

    return res.render("reset-password", {
      error: null,
      message: "Password updated successfully. You can now log in.",
      emailPrefill: "",
    });
  } catch (err) {
    return res.render("reset-password", {
      error: "Something went wrong. Please try again.",
      message: null,
      emailPrefill: email,
    });
  }
});


app.post("/resume/save", ensureAuthenticated, async (req, res) => {
  const userId = req.user.id;

  try {
    const body = req.body || {};

    const {
      resumeId,
      title,
      template,
      fullName,
      roleTitle,
      email,
      phone,
      location,
      zipCode,
      profileImageUrl,
      summary,
      experience,
      experienceJson,
      education,
      skills,
      languages,
      certifications,
      achievements,
      linkedinUrl,
      portfolioUrl,
      githubUrl,
      technologies,
      projects,
      references,
      awards,
      training,
      volunteering,
      publications,
      hobbies,
      experienceLevel,
    } = body;

    // experienceJson = JSON string of structured array (from AI Interview)
    // experience     = plain text string (from textarea)
    // Prefer structured array when both are present
    let experienceData = experience;
    if (experienceJson) {
      try {
        experienceData = JSON.parse(experienceJson);
      } catch (_) {
        experienceData = experience;
      }
    }

    const data = {
      fullName,
      roleTitle,
      email,
      phone,
      location,
      zipCode,
      profileImageUrl,
      summary,
      experience: experienceData,
      education,
      skills,
      languages,
      certifications,
      achievements,
      linkedinUrl,
      portfolioUrl,
      githubUrl,
      technologies,
      projects,
      references,
      awards,
      training,
      volunteering,
      publications,
      hobbies,
    };

    let savedId;

    if (resumeId) {
      const result = await db.query(
        `UPDATE resumes
         SET title = ?,
             template = ?,
             data = ?,
             experience_level = ?,
             updated_at = NOW()
         WHERE id = ? AND user_id = ?`,
        [title || "Untitled Resume", template || "modern-1", JSON.stringify(data), experienceLevel || "experienced", resumeId, userId]
      );

      if (result.rowCount === 0) {
        return res
          .status(404)
          .json({ success: false, error: "Resume not found." });
      }

      savedId = resumeId;
    } else {
      const result = await db.query(
        `INSERT INTO resumes (user_id, title, template, data, experience_level)
         VALUES (?, ?, ?, ?, ?)`,
        [userId, title || "Untitled Resume", template || "modern-1", JSON.stringify(data), experienceLevel || "experienced"]
      );

      savedId = result.insertId;
    }

    req.session.currentResumeId = savedId;
    req.session.resumeDraft = data;

    logActivity({
      userId,
      actionType: resumeId ? "resume_edit" : "resume_create",
      metadata: { template: template || "modern-1" },
    });

    return res.json({ success: true, resumeId: savedId });
  } catch (err) {
    return res
      .status(500)
      .json({ success: false, error: "Failed to save resume." });
  }
});

app.post("/resume/delete", ensureAuthenticated, async (req, res) => {
  const userId = req.user.id;
  const { resumeId } = req.body;
  if (!resumeId) return res.redirect("/resumes");
  try {
    await db.query(
      "DELETE FROM resumes WHERE id = ? AND user_id = ?",
      [resumeId, userId]
    );
    // Clear session if the deleted resume was the active one
    if (req.session.currentResumeId == resumeId) {
      delete req.session.currentResumeId;
      delete req.session.resumeDraft;
    }
  } catch (err) {
  }
  res.redirect("/resumes");
});

// Show resume builder form
app.get("/resume-builder", ensureAuthenticated, async (req, res) => {
  const profile = res.locals.userProfile || {};
  let draft = req.session?.resumeDraft || {};
  let template = "modern-1";

  // Load a saved resume into the builder when ?resumeId=xxx is passed (from My Resumes edit)
  if (req.query.resumeId) {
    try {
      const r = await db.query(
        "SELECT * FROM resumes WHERE id = ? AND user_id = ?",
        [req.query.resumeId, req.user.id]
      );
      if (r.rows.length > 0) {
        const saved = r.rows[0];
        draft = (saved.data && typeof saved.data === "object") ? saved.data : {};
        req.session.currentResumeId = saved.id;
        req.session.resumeDraft = draft;
        template = getTemplateById(saved.template).id;
        req.session.lastTemplate = template;
      }
    } catch (err) {
    }
  } else if (req.query.template) {
    const reqTpl = req.query.template;
    if (reqTpl.startsWith("adm-")) {
      // Admin-created template — verify it's published
      try {
        const tplRow = await db.query(
          "SELECT slug FROM admin_templates WHERE slug=? AND is_published=true", [reqTpl]
        );
        template = tplRow.rows[0] ? reqTpl : "modern-1";
      } catch (_) { template = "modern-1"; }
    } else {
      const tpl = getTemplateById(reqTpl);
      template = tpl.isAvailable ? tpl.id : "modern-1";
    }
    req.session.lastTemplate = template;
  } else if (req.session?.lastTemplate) {
    template = req.session.lastTemplate;
  } else {
    req.session.lastTemplate = template;
  }

  // For admin-created templates, fetch the section config
  let templateSections = null;
  if (template.startsWith("adm-")) {
    try {
      const tplRow = await db.query("SELECT id FROM admin_templates WHERE slug=?", [template]);
      if (tplRow.rows[0]) {
        const secRes = await db.query(
          "SELECT section_key, is_enabled, sort_order, placement, display_type, label_override FROM admin_template_sections WHERE template_id=? ORDER BY sort_order",
          [tplRow.rows[0].id]
        );
        templateSections = secRes.rows;
      }
    } catch (_) { /* ignore, show all sections */ }
  }

  res.render("resume-builder", {
    profile,
    template,
    draft,
    isPhotoTpl: isPhotoTemplate(template),
    currentUser: req.user,
    user: req.user,
    resumeId: req.session.currentResumeId || null,
    templateSections,
  });
});

app.get("/resumes", ensureAuthenticated, async (req, res, next) => {
  try {
    const userId = req.user.id;

    const result = await db.query(
      `SELECT r.id,
              r.title,
              r.template,
              r.created_at,
              r.updated_at,
              COALESCE(downloads.cnt, 0) AS downloads_count,
              COALESCE(prints.cnt, 0)    AS prints_count
       FROM resumes r
       LEFT JOIN (
         SELECT resume_id, COUNT(*) AS cnt
         FROM resume_events
         WHERE kind = 'download'
         GROUP BY resume_id
       ) downloads ON downloads.resume_id = r.id
       LEFT JOIN (
         SELECT resume_id, COUNT(*) AS cnt
         FROM resume_events
         WHERE kind = 'print'
         GROUP BY resume_id
       ) prints ON prints.resume_id = r.id
       WHERE r.user_id = ?
       ORDER BY r.updated_at DESC`,
      [userId]
    );

    res.render("resumes-list", {
      currentUser: req.user,
      resumes: result.rows,
    });
  } catch (err) {
    next(err);
  }
});

app.get("/payments", ensureAuthenticated, async (req, res, next) => {
  try {
    const userId = req.user.id;

    const result = await db.query(
      `
      SELECT
        p.id,
        p.purpose,
        p.amount,
        p.currency,
        p.status,
        p.razorpay_order_id,
        p.razorpay_payment_id,
        p.created_at,
        r.title AS resume_title,
        r.template AS resume_template
      FROM payments p
      LEFT JOIN resumes r ON r.id = p.resume_id
      WHERE p.user_id = ?
      ORDER BY p.created_at DESC
      `,
      [userId]
    );

    res.render("payments-list", {
      currentUser: req.user,
      payments: result.rows,
    });
  } catch (err) {
    next(err);
  }
});


// Template Fields API – used by AI Interview to know which questions to ask
app.get("/api/template-fields/:templateId", ensureAuthenticated, (req, res) => {
  const fields = getFieldsForTemplate(req.params.templateId);
  res.json({ success: true, fields });
});

app.get("/resume-templates", ensureAuthenticated, async (_req, res) => {
  try {
    const [adminRows, overrideRows] = await Promise.all([
      db.query("SELECT * FROM admin_templates WHERE is_published=true ORDER BY sort_order, created_at DESC"),
      db.query("SELECT * FROM template_overrides"),
    ]);

    // Apply static template overrides
    const overrideMap = Object.fromEntries(overrideRows.rows.map(o => [o.template_id, o]));
    const staticTpls = TEMPLATES.map(t => {
      const ov = overrideMap[t.id] || {};
      return {
        ...t,
        title:        ov.title          ?? t.title,
        description:  ov.description    ?? t.description,
        previewImage: ov.preview_image_url ?? t.previewImage,
        isAvailable:  ov.is_available   != null ? ov.is_available : t.isAvailable,
        badge:        ov.badge          ?? t.badge,
      };
    });

    // Map admin-created templates
    const adminTpls = adminRows.rows.map(r => ({
      id: r.slug,
      title: r.title,
      description: r.description || "",
      previewImage: r.thumbnail_url || "/images/templates/placeholder.png",
      isPaid: r.is_paid,
      isAvailable: true,
      badge: r.badge || "New",
      category: r.category,
    }));

    res.render("resume-templates", { RESUME_TEMPLATES: [...staticTpls, ...adminTpls] });
  } catch (err) {
    res.render("resume-templates", { RESUME_TEMPLATES: TEMPLATES });
  }
});

// ---------- Photo Editor ----------
app.get("/photo-editor", ensureAuthenticated, (req, res) => {
  res.render("photo-editor");
});

// ---------- Background Remover ----------
app.get("/background-remover", ensureAuthenticated, async (req, res) => {
  try {
    const r = await db.query("SELECT value FROM admin_settings WHERE `key`='bgremover_backgrounds'");
    const bgImages = r.rows.length ? JSON.parse(r.rows[0].value) : [];
    res.render("background-remover", { bgImages });
  } catch {
    res.render("background-remover", { bgImages: [] });
  }
});

app.post("/api/background-remover", ensureAuthenticated, upload.single("image"), async (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, error: "No image uploaded" });
  const b64 = req.file.buffer
    ? req.file.buffer.toString("base64")
    : fs.readFileSync(req.file.path).toString("base64");
  if (req.file.path) { try { fs.unlinkSync(req.file.path); } catch (_) {} }

  let provider = 'removebg';
  try {
    const pr = await db.query("SELECT value FROM admin_settings WHERE `key`='bgremover_provider'");
    if (pr.rows.length) provider = pr.rows[0].value;
  } catch (_) {}

  try {
    if (provider === 'free') {
      const imgBuffer = Buffer.from(b64, "base64");
      const imgBlob = new Blob([imgBuffer], { type: req.file.mimetype || 'image/jpeg' });
      const removeBackground = await getRemoveBg();
      const blob = await removeBackground(imgBlob);
      const arrayBuffer = await blob.arrayBuffer();
      const b64out = Buffer.from(arrayBuffer).toString("base64");
      res.json({ success: true, image: `data:image/png;base64,${b64out}` });
    } else {
      const bgResult = await removeBackgroundFromImageBase64({
        base64img: b64,
        apiKey: process.env.REMOVEBG_API_KEY,
        size: "regular",
        type: "auto",
      });
      res.json({ success: true, image: `data:image/png;base64,${bgResult.base64img}` });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message || "Background removal failed" });
  }
});

// ---------- Application Builder ----------
app.get("/application-builder", ensureAuthenticated, (req, res) => {
  const profile = res.locals.userProfile || {};
  res.render("application-builder", {
    currentUser: req.user,
    user: req.user,
    profile,
  });
});


app.post("/application-builder/preview", ensureAuthenticated, (req, res) => {
  const data = req.body || {};
  res.render("application-preview", {
    currentUser: req.user,
    user: req.user,
    data,
  });
});

// Show preview after form submit
app.post("/resume-builder/preview", ensureAuthenticated, async (req, res) => {
  const data = req.body;
  const rawTemplate = data.template || req.session?.lastTemplate || "modern-1";
  const isAdminTpl = rawTemplate.startsWith("adm-");
  const template = isAdminTpl ? rawTemplate : getTemplateById(rawTemplate).id;

  // For admin templates, fetch config + section config for the renderer
  let adminTemplateConfig = null;
  let templateSections = null;
  if (isAdminTpl) {
    try {
      const tplRow = await db.query("SELECT * FROM admin_templates WHERE slug=?", [template]);
      adminTemplateConfig = tplRow.rows[0] || null;
      if (adminTemplateConfig) {
        const secRes = await db.query(
          "SELECT section_key, is_enabled, sort_order, placement, display_type, label_override FROM admin_template_sections WHERE template_id=? ORDER BY sort_order",
          [adminTemplateConfig.id]
        );
        templateSections = secRes.rows;
      }
    } catch (_) { /* fallback gracefully */ }
  }

  try {
    // upsert profile
    await db.query(
      `INSERT INTO user_profiles
        (user_id, full_name, role_title, location, phone, email, summary,
         experience, education, languages, skills, profile_image_url, updated_at)
       VALUES
        (?,?,?,?,?,?,?,?,?,?,?,?, NOW())
       ON DUPLICATE KEY UPDATE
        full_name=VALUES(full_name),
        role_title=VALUES(role_title),
        location=VALUES(location),
        phone=VALUES(phone),
        email=VALUES(email),
        summary=VALUES(summary),
        experience=VALUES(experience),
        education=VALUES(education),
        languages=VALUES(languages),
        skills=VALUES(skills),
        profile_image_url=VALUES(profile_image_url),
        updated_at=NOW()`,
      [
        req.user.id,
        data.fullName,
        data.roleTitle,
        data.location,
        data.phone,
        data.email,
        data.summary,
        data.experience,
        data.education,
        data.languages,
        data.skills,
        data.profileImageUrl ||
          (res.locals.userProfile && res.locals.userProfile.profile_image_url) ||
          null,
      ]
    );

    // save draft + template in session so builder can prefill next time
    req.session.resumeDraft = data;
    req.session.lastTemplate = template;

    // Generate QR code from portfolio or GitHub URL
    let qrCodeDataUrl = null;
    const qrTarget = (data.portfolioUrl || data.githubUrl || "").trim();
    if (qrTarget) {
      try {
        qrCodeDataUrl = await QRCode.toDataURL(qrTarget, {
          width: 110,
          margin: 1,
          color: { dark: "#0f172a", light: "#ffffff" },
        });
      } catch (_) { /* ignore QR errors */ }
    }

    // Read dynamic price
    let displayPrice = 100;
    if (isAdminTpl && adminTemplateConfig) {
      // Admin-created template: use its own price_inr
      displayPrice = adminTemplateConfig.is_paid ? (adminTemplateConfig.price_inr || 49) : 0;
    } else {
      // Static template: read from admin_settings by category
      const tplCategory = getTemplateById(template).category || "experienced";
      const priceKey = `price_${tplCategory}`;
      try {
        const priceRes = await db.query("SELECT value FROM admin_settings WHERE `key` = ?", [priceKey]);
        if (priceRes.rows.length) displayPrice = parseInt(priceRes.rows[0].value, 10);
      } catch (_) { /* ignore, use default */ }
    }

    // Fetch background image URL for this template
    let bgImageUrl = null;
    if (isAdminTpl && adminTemplateConfig) {
      bgImageUrl = adminTemplateConfig.background_image_url || null;
    } else {
      try {
        const ovRow = await db.query("SELECT background_image_url FROM template_overrides WHERE template_id=?", [template]);
        bgImageUrl = ovRow.rows[0]?.background_image_url || null;
      } catch (_) { /* ignore */ }
    }

    const walletRow2 = await db.query("SELECT wallet_balance FROM users WHERE id=?", [req.user.id]).catch(() => ({ rows: [] }));
    const walletBalance = parseFloat(walletRow2.rows[0]?.wallet_balance) || 0;
    res.render("resume-preview", { data, template, qrCodeDataUrl, displayPrice, adminTemplateConfig, templateSections, bgImageUrl, walletBalance });
  } catch (err) {
    res.send("Error while saving profile.");
  }
});


app.post("/resume-builder/pdf", ensureAuthenticated, async (req, res) => {
  const {
    resumeId,
    fullName,
    email,
    phone,
    summary,
    experience,
    experienceJson,
    education,
    skills,
    profileImageUrl,
  } = req.body;

  // Resolve experience: prefer structured JSON array when present
  let experienceData = experience;
  if (experienceJson) {
    try {
      experienceData = JSON.parse(experienceJson);
    } catch (_) {
      experienceData = experience;
    }
  }

  /* 🔐 PAYMENT CHECK (MANDATORY) */
  const pay = await db.query(
    `SELECT status
     FROM payments
     WHERE user_id = ?
       AND resume_id = ?
     ORDER BY created_at DESC
     LIMIT 1`,
    [req.user.id, resumeId]
  );

  if (!pay.rows.length || pay.rows[0].status !== "captured") {
    return res.status(403).send("Payment not completed");
  }

  /* ✅ PAYMENT CONFIRMED → GENERATE PDF (multi-page) */
  const margin = 50;
  const doc = new PDFDocument({
    size: "A4",
    margin,
    bufferPages: true,
  });

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader(
    "Content-Disposition",
    'attachment; filename="SmrAI-Studio-Resume.pdf"'
  );

  doc.pipe(res);

  // --- Helper: check remaining space, add page if needed ---
  const pageBottom = doc.page.height - margin;
  function ensureSpace(needed) {
    if (doc.y + needed > pageBottom) {
      doc.addPage();
    }
  }

  // Only add vertical gap when not already at the top of a fresh page.
  // Prevents blank space appearing at the start of a page after PDFKit
  // automatically wrapped long text onto a new page.
  function safeDown(lines) {
    if (doc.y > margin + 12) doc.moveDown(lines);
  }

  // --- Helper: draw a section heading + body text ---
  function drawSection(title, body) {
    if (!body || !body.trim()) return;
    // heading (~16pt) + separator (~8pt) + 2 minimum body lines — avoids orphaned heads
    ensureSpace(60);
    doc
      .fontSize(13)
      .font("Helvetica-Bold")
      .text(title)
      .moveDown(0.2);
    // Thin separator line
    doc
      .strokeColor("#d1d5db")
      .lineWidth(0.5)
      .moveTo(margin, doc.y)
      .lineTo(doc.page.width - margin, doc.y)
      .stroke();
    doc.moveDown(0.3);
    doc
      .fontSize(10.5)
      .font("Helvetica")
      .text(body, { align: "left", lineGap: 3 });
    // Don't add bottom gap if PDFKit just broke onto a new page mid-text
    safeDown(0.8);
  }

  // === Profile photo (optional) ===
  if (profileImageUrl && typeof profileImageUrl === "string") {
    try {
      const photoSize = 72;
      const photoX = (doc.page.width - photoSize) / 2;
      if (profileImageUrl.startsWith("data:")) {
        // base64 data URL — decode to buffer for PDFKit
        const base64Data = profileImageUrl.split(",")[1];
        const imgBuf = Buffer.from(base64Data, "base64");
        doc.image(imgBuf, photoX, margin, { width: photoSize, height: photoSize });
      } else if (profileImageUrl.startsWith("/uploads/")) {
        const imgPath = path.join(__dirname, "public", profileImageUrl);
        if (fs.existsSync(imgPath)) {
          doc.image(imgPath, photoX, margin, { width: photoSize, height: photoSize });
        }
      }
      doc.y = margin + photoSize + 10;
    } catch (_) { /* skip if image unreadable */ }
  }

  // === Header ===
  doc
    .fontSize(22)
    .font("Helvetica-Bold")
    .text(fullName || "", { align: "center" });
  doc.moveDown(0.3);

  const contactParts = [email, phone].filter(Boolean);
  if (contactParts.length) {
    doc
      .fontSize(10)
      .font("Helvetica")
      .text(contactParts.join("  |  "), { align: "center" });
  }
  doc.moveDown(1);

  // === Sections (auto-paginates) ===
  drawSection("Summary", summary);

  // --- Experience: handle both array (AI Interview) and string (textarea) ---
  if (Array.isArray(experienceData) && experienceData.length) {
    // Reserve space for heading + separator + at least the first item's title line
    ensureSpace(80);
    doc.fontSize(13).font("Helvetica-Bold").text("Experience").moveDown(0.2);
    doc.strokeColor("#d1d5db").lineWidth(0.5)
       .moveTo(margin, doc.y).lineTo(doc.page.width - margin, doc.y).stroke();
    doc.moveDown(0.3);

    for (const item of experienceData) {
      // Reserve space for job title + 2 description lines before allowing natural wrap
      ensureSpace(55);
      const parts = [item.title, item.company, item.dates].filter(Boolean);
      doc.fontSize(11).font("Helvetica-Bold").text(parts.join("  ·  ")).moveDown(0.15);
      if (item.description) {
        // Apply same line cleanup as the preview (trim each line, drop blanks)
        const cleanDesc = item.description
          .split(/\r?\n/)
          .map(l => l.trim())
          .filter(l => l.length > 0)
          .join("\n");
        doc.fontSize(10.5).font("Helvetica")
           .text(cleanDesc, { align: "left", lineGap: 3 });
        safeDown(0.6);
      } else {
        safeDown(0.4);
      }
    }
    safeDown(0.5);
  } else if (typeof experienceData === "string") {
    drawSection("Experience", experienceData);
  }

  drawSection("Education", education);
  drawSection("Skills", skills);

  doc.end();
});



// Google Auth
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["email", "profile"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    const redirectTo = req.session.returnTo || "/dashboard";
    delete req.session.returnTo;
    res.redirect(redirectTo);
  }
);

// ── Site URL helper — reads from admin_settings first, then process.env ──────
async function getSiteUrl() {
  try {
    const r = await db.query("SELECT value FROM admin_settings WHERE `key`='env_base_url'");
    if (r.rows[0]?.value) return r.rows[0].value.replace(/\/$/, '');
  } catch (_) {}
  return (process.env.BASE_URL || 'https://smrai.studio').replace(/\/$/, '');
}

// ── Referral code generator ──────────────────────────────────────────────────
function generateReferralCode(name, userId, attempt = 0) {
  const prefix = (name || 'SMR').replace(/[^A-Za-z]/g, '').toUpperCase().slice(0, 3).padEnd(3, 'X');
  const seed = (userId * 7919 + attempt * 1031 + Math.floor(Math.random() * 9999));
  const suffix = seed.toString(36).toUpperCase().slice(-5).padStart(5, '0');
  return prefix + suffix; // e.g. "JOH3K9XM" — always 8 chars
}

// ── Auth guards ─────────────────────────────────────────────────────────────
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  req.session.returnTo = req.originalUrl;
  req.session.save(() => res.redirect("/login"));
}

function ensureAdmin(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect("/login");
  if (req.user.role === "admin" || req.user.role === "subadmin") return next();
  res.status(403).render("403");
}

function ensureInvestorApproved(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect("/login");
  if (req.user.investor_approved) return next();
  return res.redirect("/dashboard");
}

function ensureInvestor(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect("/login");
  if (req.user.role === "investor" || req.user.role === "admin") return next();
  return res.redirect("/dashboard");
}

// ── Activity logger (non-critical — never crashes a request) ─────────────────
async function logActivity({ userId = null, actionType, route = null, metadata = null, ip = null } = {}) {
  try {
    await db.query(
      `INSERT INTO activity_logs (user_id, action_type, route, metadata, ip_address)
       VALUES (?, ?, ?, ?, ?)`,
      [userId, actionType, route, metadata ? JSON.stringify(metadata) : null, ip]
    );
  } catch (_) {}
}

// ── Page-visit tracking (deduped: same user+route only logged once per 5 min) ─
const visitCache = new Map(); // key: "userId:route" → last logged timestamp
app.use((req, res, next) => {
  if (
    req.method === "GET" &&
    !req.path.startsWith("/api/") &&
    !req.path.startsWith("/admin/api/") &&
    !req.path.startsWith("/css/") &&
    !req.path.startsWith("/js/") &&
    !req.path.startsWith("/images/") &&
    !req.path.startsWith("/fonts/") &&
    !req.path.includes(".")
  ) {
    // Use session ID (or IP fallback) so each anonymous visitor is tracked separately
    const uid = req.user?.id ?? req.sessionID ?? req.ip ?? "anon";
    const key = `${uid}:${req.path}`;
    const last = visitCache.get(key) ?? 0;
    const now  = Date.now();
    if (now - last > 5 * 60 * 1000) {   // 5-minute cooldown per visitor+route
      visitCache.set(key, now);
      // For guests: store anonymised session fragment in metadata so admin can count unique visitors
      const meta = req.user ? null : { sid: (req.sessionID || req.ip || "").slice(-10) };
      logActivity({ userId: req.user?.id ?? null, actionType: "visit", route: req.path, ip: req.ip, metadata: meta });
    }
  }
  next();
});

app.get("/dashboard", ensureAuthenticated, async (req, res) => {
  let subadminInvestment = null;
  let subadminProfile = null;
  if (req.user.role === "subadmin") {
    const [inv, profile] = await Promise.all([
      db.query("SELECT * FROM investments WHERE user_id=? ORDER BY created_at DESC LIMIT 1", [req.user.id]),
      db.query("SELECT full_name, profile_image_url FROM user_profiles WHERE user_id=?", [req.user.id]),
    ]);
    subadminInvestment = inv.rows[0] || null;
    subadminProfile = profile.rows[0] || null;
  }
  const walletRow = await db.query("SELECT wallet_balance FROM users WHERE id=?", [req.user.id]).catch(() => ({ rows: [] }));
  const walletBalance = parseFloat(walletRow.rows[0]?.wallet_balance) || 0;
  res.render("dashboard", { subadminInvestment, subadminProfile, walletBalance });
});

app.get("/wallet", ensureAuthenticated, async (req, res) => {
  try {
    const [walletRow, txRows, refRow] = await Promise.all([
      db.query("SELECT wallet_balance FROM users WHERE id=?", [req.user.id]),
      db.query("SELECT * FROM wallet_transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 50", [req.user.id]),
      db.query("SELECT COUNT(*) AS count FROM users WHERE referred_by=?", [req.user.id]),
    ]);
    const walletBalance = parseFloat(walletRow.rows[0]?.wallet_balance) || 0;
    const transactions = txRows.rows;
    const invitedCount = parseInt(refRow.rows[0]?.count) || 0;
    const referralUrl = `${process.env.BASE_URL || "http://localhost:3000"}/register?ref=${req.user.referral_code || ""}`;
    res.render("wallet", { walletBalance, transactions, invitedCount, referralUrl, user: req.user });
  } catch (err) {
    res.render("wallet", { walletBalance: 0, transactions: [], invitedCount: 0, referralUrl: "", user: req.user });
  }
});

// Logout
app.post("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) return next(err);

    req.session.destroy(() => {
      res.clearCookie("connect.sid"); // name of the session cookie
      res.redirect("/login");
    });
  });
});

// Log free resume events (download / print for non-paid templates)
app.post("/resume/event", ensureAuthenticated, async (req, res) => {
  const userId = req.user.id;
  const { kind, resumeId } = req.body || {};

  if (!kind) {
    return res.status(400).json({ success: false, message: "kind is required" });
  }

  try {
    await db.query(
      `INSERT INTO resume_events (user_id, resume_id, kind)
       VALUES (?, ?, ?)`,
      [userId, resumeId || null, kind]
    );

    logActivity({ userId, actionType: "download_" + kind, metadata: { resumeId: resumeId || null } });

    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ success: false });
  }
});
// ---------- AI Resume Suggestion Route ----------
app.post("/api/ai/suggest", ensureAuthenticated, async (req, res) => {
  const { field, currentText, roleTitle, experienceLevel, experience } = req.body || {};

  if (!field) {
    return res.status(400).json({ success: false, message: "field is required" });
  }

  if (!geminiModel) {
    return res.status(503).json({ success: false, message: "AI features are currently unavailable. Please try again later." });
  }

  // ── Experience field: structured JSON response ──────────────────────────
  if (field === "experience") {
    // ── Empty experience: generate a sample entry from scratch ──────────────
    if (!currentText || !currentText.trim()) {
      const sampleExpPrompt = `You are a professional resume writer creating a sample work history entry.
The candidate has not entered any experience yet.
Job title context: ${roleTitle || "Professional"}
Generate ONE realistic sample work experience entry for this role.
Return ONLY a valid JSON array — no markdown, no prose, no code fences:
[{"title":"<fitting job title>","company":"<plausible company>","dates":"2022 – Present","description":"• <action-verb responsibility 1>\n• <action-verb responsibility 2>\n• <action-verb responsibility 3>"}]`;
      try {
        const sampleResult = await geminiModel.generateContent({
          contents: [{ role: "user", parts: [{ text: sampleExpPrompt }] }],
          generationConfig: { temperature: 0.65, maxOutputTokens: 512, responseMimeType: "application/json" },
        });
        let raw = sampleResult.response?.candidates?.[0]?.content?.parts?.[0]?.text || "[]";
        raw = raw.replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/, "").trim();
        let structured = [];
        try { structured = JSON.parse(raw); } catch (_) { structured = []; }
        if (!Array.isArray(structured) || structured.length === 0) {
          structured = [{ title: roleTitle || "Professional", company: "", dates: "2022 – Present", description: "" }];
        }
        const readableText = structured.map(item => {
          const header = [item.title || "", item.company ? "— " + item.company : "", item.dates ? "(" + item.dates + ")" : ""].filter(Boolean).join(" ");
          return item.description ? header + "\n" + item.description : header;
        }).join("\n\n");
        return res.json({ success: true, text: readableText, structured });
      } catch (err) {
        const errMsg = err.message || "";
        if (errMsg.includes("RESOURCE_EXHAUSTED") || errMsg.includes("429") || errMsg.includes("quota")) {
          return res.json({ success: false, error: "insufficient_quota" });
        }
        return res.json({ success: false, error: "AI error: " + (err.message || "Unknown error") });
      }
    }
    // ── Non-empty experience: structure the candidate's text ─────────────────
    const experiencePrompt = `You are a professional resume writer helping structure a candidate's work history.

The candidate has described their experience in natural, informal language:
"""${currentText || ""}"""

Job title context (if known): ${roleTitle || "Not specified"}

Your tasks:
1. Identify every distinct job role or position mentioned.
2. For each role, return exactly these four fields:
   - "title"   : the job title (use Title Case).
   - "company" : the organisation name as stated, or inferred from common knowledge
                 (e.g. "CSC" context → "Common Service Centre"; keep well-known brand names as-is).
                 Use "" only if truly unknown.
   - "dates"   : normalize to "YYYY \u2013 YYYY" or "YYYY \u2013 Present" format.
                 Convert natural phrasing: "from 2017 to 2019", "2017-2019",
                 "2024 to present", "till date" etc. Capitalize "Present".
   - "description" : 2\u20134 concise, professional bullet points as a single string.
                 Each bullet on its own line starting with "\u2022" (bullet character, not hyphen).
                 Use strong action verbs.
                 Base bullets on:
                   a) What the candidate explicitly mentioned about this role.
                   b) Typical core responsibilities for this role and industry,
                      when the candidate did not provide detail.
                 Keep bullets realistic \u2014 do not invent companies or titles.
3. If only one role is mentioned, return a single-item array.
4. If you cannot confidently split multiple roles, return one item using the job title context.
5. List roles in chronological order (oldest first).

Return ONLY a valid JSON array \u2014 no markdown, no prose, no code fences:
[{"title":"...","company":"...","dates":"...","description":"\u2022 ...\n\u2022 ..."}]`;

    try {
      const result = await geminiModel.generateContent({
        contents: [{ role: "user", parts: [{ text: experiencePrompt }] }],
        generationConfig: {
          temperature: 0.45,
          maxOutputTokens: 1536,
          responseMimeType: "application/json",
        },
      });

      let raw = result.response?.candidates?.[0]?.content?.parts?.[0]?.text || "[]";
      // Strip accidental markdown fences just in case
      raw = raw.replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/, "").trim();

      let structured = [];
      try { structured = JSON.parse(raw); } catch (_) { structured = []; }

      // Fallback: wrap the raw text into a single entry if parsing failed
      if (!Array.isArray(structured) || structured.length === 0) {
        structured = [{
          title:       roleTitle || "Position",
          company:     "",
          dates:       "",
          description: currentText ? "\u2022 " + currentText.trim().split(/\n+/).join("\n\u2022 ") : "",
        }];
      }

      // Build human-readable textarea text from the structured array
      const readableText = structured.map(item => {
        const header = [
          item.title   || "",
          item.company ? "\u2014 " + item.company : "",
          item.dates   ? "(" + item.dates + ")"   : "",
        ].filter(Boolean).join(" ");
        return item.description ? header + "\n" + item.description : header;
      }).join("\n\n");

      return res.json({ success: true, text: readableText, structured });
    } catch (err) {
      const errMsg = err.message || "";
      if (errMsg.includes("RESOURCE_EXHAUSTED") || errMsg.includes("429") || errMsg.includes("quota")) {
        return res.json({ success: false, error: "insufficient_quota" });
      }
      return res.json({ success: false, error: "AI error: " + (err.message || "Unknown error") });
    }
  }

  // Build field-specific instructions
  let fieldInstructions = "";

  switch (field) {
    case "summary":
      fieldInstructions = `
        You are writing a professional resume SUMMARY.
        Role: ${roleTitle || "Not specified"}.
        ${currentText && currentText.trim()
          ? `The candidate wrote: """${currentText}"""
        Improve or extend this into a crisp 3–5 line professional summary.`
          : `The candidate has not written a summary yet.
        Generate a crisp 3–5 line professional summary for a ${roleTitle || "professional"}.`}
        Focus on achievements, strengths, and domain expertise.
        Do not use "I". Write in a neutral tone (e.g. "Results-driven professional...").
        Return plain text only, with line breaks, no bullets or numbering.
      `;
      break;

    case "education":
      fieldInstructions = `
        You are writing the EDUCATION section of a resume.
        ${currentText && currentText.trim()
          ? `The candidate wrote: """${currentText}"""
        Format and improve it as clean lines like:
        "2018 – B.Com, XYZ College, Bangalore"
        "2016 – Higher Secondary, ABC School"
        One entry per line, most recent first.`
          : `The candidate has not entered any education details yet.
        Role context: ${roleTitle || "Not specified"}.
        Generate 2–3 realistic sample education entries in this format:
        "2020 – B.Tech Computer Science, XYZ University"
        "2018 – Higher Secondary (Science), ABC School"
        Most recent first.`}
        Return plain text only, one entry per line.
      `;
      break;

    case "skills":
      fieldInstructions = `
        You are writing the SKILLS section of a resume.
        ${currentText && currentText.trim()
          ? `The candidate listed: """${currentText}"""
        Improve and expand this into a polished, ATS-friendly skills list.
        Return as a clean comma-separated list. No bullets, no numbering, no explanation.`
          : experience && experience.trim()
            ? `Based on the following work experience:
        """${experience}"""
        Generate 8–12 realistic, ATS-friendly professional skills directly derived from this experience.
        Do not invent unrelated skills.
        Return as a clean comma-separated list. No bullets, no numbering, no explanation.`
            : `Generate 8–12 key professional skills relevant to the role: "${roleTitle || "professional"}".
        Return as a clean comma-separated list. No bullets, no numbering, no explanation.`}
      `;
      break;

    case "languages":
      fieldInstructions = `
        You are writing the LANGUAGES section of a resume.
        ${currentText && currentText.trim()
          ? `The candidate wrote: """${currentText}"""
        Format and improve it. List languages in the format:
        "English – Read, Write, Speak"
        "Hindi – Read, Speak"
        One language per line.`
          : `The candidate has not entered any languages yet.
        Suggest a realistic set of 2–3 languages for a professional, in this format:
        "English – Read, Write, Speak"
        "Hindi – Read, Write, Speak"
        One language per line.`}
        Return plain text only.
      `;
      break;

    case "references":
      fieldInstructions = `
        You are writing the REFERENCES section of a resume.
        ${currentText && currentText.trim()
          ? `The candidate wrote: """${currentText}"""
        Format and improve it. Each referee must follow this exact structure (one field per line):
        Name
        Institution / Company
        Phone number
        Website or email
        Separate multiple referees with --- on its own line.`
          : `The candidate has not entered any references yet.
        Generate 2 realistic sample referee entries.
        Each referee must follow this exact structure (one field per line):
        Name
        Institution / Company
        Phone number
        Website or email
        Separate the two referees with --- on its own line.
        Example:
        Rufus Stewart
        Borcelle University
        +123-456-7890
        www.borcelle.com
        ---
        Lorna Alvarado
        Greenfield Institute
        +098-765-4321
        www.greenfield.edu`}
        Return plain text only, no bullet symbols, no labels, no extra explanation.
      `;
      break;

    case "technologies":
      fieldInstructions = `
        You are writing the TECHNOLOGIES / STACK section of a software developer resume.
        Format: One category per line with comma-separated technologies on the right of a colon.
        Example:
        Frontend: React, TypeScript, Tailwind CSS
        Backend: Node.js, Express.js, Python
        Database: PostgreSQL, MongoDB
        DevOps: Docker, AWS, GitHub Actions
        Tools: Git, Postman, VS Code

        ${currentText && currentText.trim()
          ? `The candidate listed: """${currentText}"""
        Improve, expand, and format this into clean category lines.`
          : `Role context: ${roleTitle || "Software Engineer"}.
        ${experience && experience.trim()
          ? `Their experience: """${experience}"""
        Infer the tech stack from their experience and generate realistic categories.`
          : `Generate 5–6 realistic technology categories for a ${roleTitle || "Software Engineer"}.`}`}
        Return plain text only — one "Category: skill1, skill2" line per row, no extra explanation.
      `;
      break;

    case "projects":
      fieldInstructions = `
        You are writing the PROJECTS section of a software developer resume.
        Each project must follow this exact format:
        Project Name | Tech: tech1, tech2, tech3 | https://github.com/user/repo
        One or two sentence description of what was built.
        • Bullet point achievement or feature
        • Another bullet point
        (blank line between projects)

        ${currentText && currentText.trim()
          ? `The candidate wrote: """${currentText}"""
        Improve and reformat this into the above structure.`
          : `Role context: ${roleTitle || "Software Engineer"}.
        ${experience && experience.trim()
          ? `Their experience mentions: """${experience}"""
        Generate 2–3 realistic projects that a ${roleTitle || "Software Engineer"} with this background might have built.`
          : `Generate 2–3 realistic projects for a ${roleTitle || "Software Engineer"}.`}`}
        Return plain text only — follow the format exactly. No markdown headers or extra labels.
      `;
      break;

    case "certifications":
      fieldInstructions = `
        You are writing the CERTIFICATIONS & ACHIEVEMENTS section of a developer resume.
        Each certification on its own line, formatted as:
        "Certification Name — YEAR"
        Example:
        AWS Certified Solutions Architect – Associate — 2024
        Google Professional Cloud Developer — 2023
        Meta React Developer Certificate — 2022

        ${currentText && currentText.trim()
          ? `The candidate listed: """${currentText}"""
        Improve and format this list.`
          : `Role context: ${roleTitle || "Software Engineer"}.
        Suggest 3–4 relevant, realistic certifications for a ${roleTitle || "Software Engineer"}.`}
        Return plain text only — one certification per line, no bullets, no explanation.
      `;
      break;

    default:
      fieldInstructions = `
        You are helping complete a resume field: ${field}.
        ${currentText && currentText.trim()
          ? `The candidate wrote: """${currentText}"""
        Improve or extend this text to look professional and concise.`
          : `The candidate has not entered anything yet for this field.
        Role context: ${roleTitle || "Not specified"}.
        Generate professional, realistic sample content for a "${field}" field on a resume.
        Keep it concise and suitable for a resume.`}
        Return plain text only, suitable for a resume.
      `;
      break;
  }

  try {
    const result = await geminiModel.generateContent({
      contents: [
        {
          role: "user",
          parts: [
            {
              text:
                "You are a helpful resume-writing assistant.\n\n" +
                fieldInstructions,
            },
          ],
        },
      ],
      generationConfig: {
        temperature: 0.7,
        maxOutputTokens: 1024,
      },
    });

    const suggestion =
      result.response?.candidates?.[0]?.content?.parts?.[0]?.text || "";
    logActivity({ userId: req.user.id, actionType: "ai_use", route: req.path });
    return res.json({ success: true, text: suggestion.trim() });
  } catch (err) {

    const errMsg = err.message || "";
    if (
      errMsg.includes("RESOURCE_EXHAUSTED") ||
      errMsg.includes("429") ||
      errMsg.includes("quota")
    ) {
      return res.json({
        success: false,
        error: "insufficient_quota",
      });
    }

    return res.json({
      success: false,
      error: "AI error: " + (err.message || "Unknown error"),
    });
  }
});


// ---------- AI Interview Prompt Builder ----------
function buildInterviewPrompt(answers, templateId) {
  const fields = getFieldsForTemplate(templateId);
  const fieldList = fields.map(f => f.key).join(", ");

  const answerText = Object.entries(answers)
    .map(([k, v]) => `${k}: ${String(v).trim()}`)
    .join("\n");

  return `You are an expert resume writer. Based on the candidate's interview answers below, generate a complete, professional resume as JSON.

Template: ${templateId}
Required fields: ${fieldList}

Candidate answers:
${answerText}

Return ONLY valid JSON matching this exact schema (no markdown, no commentary):
{
  "fullName": "string",
  "roleTitle": "string",
  "phone": "string",
  "email": "string",
  "location": "string",
  "summary": "3-5 line professional summary using action words, no first-person pronouns",
  "experience": [
    {
      "title": "Job Title",
      "company": "Company Name",
      "dates": "Month Year – Month Year or Present",
      "description": "Key achievements and responsibilities in 1-2 concise sentences using action verbs."
    }
  ],
  "education": "Degree, Institution, Year\\nDegree, Institution, Year (one entry per line, newest first)",
  "skills": "Skill 1\\nSkill 2\\nSkill 3 (one skill per line, 6-12 skills relevant to the role)",
  "languages": "English – Read, Write, Speak\\nHindi – Read, Speak (one language per line)"
}`;
}

// ---------- AI Application Suggestion Route ----------
app.post("/api/ai/suggest-application", ensureAuthenticated, async (req, res) => {
  const {
    appType, fromName, fromDesignation, fromDept,
    toName, toDesignation, orgName, subject, currentBody
  } = req.body || {};

  if (!geminiModel) {
    return res.status(503).json({ success: false, error: "AI features are currently unavailable. Please try again later." });
  }

  const TYPE_LABELS = {
    "sick-leave":        "sick leave application",
    "casual-leave":      "casual / personal leave application",
    "week-off":          "week off request letter",
    "month-off":         "extended leave application",
    "resignation":       "resignation letter",
    "appreciation":      "letter of appreciation",
    "transfer-request":  "transfer request letter",
    "promotion-request": "promotion request letter",
    "school-leave":      "school / college leave application",
    "noc-request":       "NOC (No Objection Certificate) request letter",
    "custom":            "formal application letter",
  };

  const typeLabel = TYPE_LABELS[appType] || "formal application letter";
  const resolvedSubject = subject || typeLabel;

  const prompt = `You are an expert writer of formal professional/academic application letters.

Write a complete, polished ${typeLabel} body for the following person.

From: ${fromName || "the applicant"}${fromDesignation ? ", " + fromDesignation : ""}${fromDept ? ", " + fromDept : ""}
To: ${toName || "the authority"}${toDesignation ? ", " + toDesignation : ""}${orgName ? " at " + orgName : ""}
Subject: ${resolvedSubject}

${currentBody && currentBody.trim()
  ? `The applicant has already written the following draft. Improve and expand it into a professional, complete letter body:\n"""${currentBody}"""`
  : `Generate a professional, complete letter body. Include an opening sentence, the main reason/request with relevant details, and a polite closing request.`}

RULES:
- Write ONLY the letter body — do NOT include date, To/From address, subject line, salutation (Respected Sir/Madam), or closing (Yours sincerely / signature). Just the paragraphs.
- Use formal, polite, professional English.
- Be concise but complete. 2–4 paragraphs maximum.
- Do not use placeholder text like "[reason]" — write naturally without filler.
- Return plain text only — no markdown, no bullets, no numbering.`;

  try {
    const result = await geminiModel.generateContent({
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.55, maxOutputTokens: 800 },
    });

    const text = result.response?.candidates?.[0]?.content?.parts?.[0]?.text || "";
    if (!text.trim()) {
      return res.json({ success: false, error: "AI returned an empty response. Please try again." });
    }

    logActivity({ userId: req.user.id, actionType: "ai_use", route: req.path });
    return res.json({ success: true, text: text.trim() });
  } catch (err) {
    const errMsg = err.message || "";
    if (errMsg.includes("RESOURCE_EXHAUSTED") || errMsg.includes("429") || errMsg.includes("quota")) {
      return res.json({ success: false, error: "AI quota limit reached. Please try again in a moment." });
    }
    return res.json({ success: false, error: "AI error: " + (err.message || "Unknown error") });
  }
});

// ---------- AI Interview Generate Route ----------
app.post("/api/ai/interview-generate", ensureAuthenticated, async (req, res) => {
  const { answers, templateId } = req.body || {};

  if (!answers || !templateId) {
    return res.status(400).json({ success: false, message: "answers and templateId are required" });
  }

  try {
    const prompt = buildInterviewPrompt(answers, templateId);

    const result = await geminiModel.generateContent({
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.7,
        maxOutputTokens: 2048,
        responseMimeType: "application/json",
      },
    });

    const raw = result.response?.candidates?.[0]?.content?.parts?.[0]?.text || "";

    // Strip markdown fences if Gemini wraps in ```json ... ```
    let resumeData;
    try {
      const cleaned = raw.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
      resumeData = JSON.parse(cleaned);
    } catch (_) {
      return res.status(500).json({ success: false, error: "Failed to parse AI response as JSON" });
    }

    return res.json({ success: true, data: resumeData });
  } catch (err) {
    const errMsg = err.message || "";
    if (errMsg.includes("RESOURCE_EXHAUSTED") || errMsg.includes("429") || errMsg.includes("quota")) {
      return res.json({ success: false, error: "insufficient_quota" });
    }
    return res.json({ success: false, error: "AI error: " + (err.message || "Unknown error") });
  }
});


// ── Investor System ───────────────────────────────────────────────────────────

// Helper: load investment config from admin_settings
async function getInvestmentConfig() {
  const rows = await db.query(
    "SELECT `key`, value FROM admin_settings WHERE `key` IN ('investment_amount','investment_equity','investment_valuation')"
  );
  const cfg = {};
  for (const r of rows.rows) cfg[r.key] = parseFloat(r.value);
  return {
    amount:   cfg.investment_amount   || 50000,
    equity:   cfg.investment_equity   || 40,
    valuation: cfg.investment_valuation || 125000,
  };
}

// POST /investor/request — logged-in user requests investor access
app.post("/investor/request", ensureAuthenticated, async (req, res) => {
  try {
    const desiredAmount = parseFloat(req.body.desired_amount) || null;
    const cfg = await getInvestmentConfig();
    const desiredEquity = desiredAmount ? parseFloat(((desiredAmount / cfg.valuation) * 100).toFixed(2)) : null;
    const phone = (req.body.phone || '').trim().replace(/\D/g, '').slice(0, 20) || null;
    await db.query(
      `INSERT INTO investor_requests (user_id, status, desired_amount, desired_equity, phone)
       VALUES (?, 'pending', ?, ?, ?)
       ON DUPLICATE KEY UPDATE status='pending', desired_amount=VALUES(desired_amount), desired_equity=VALUES(desired_equity), phone=VALUES(phone), updated_at=NOW()`,
      [req.user.id, desiredAmount, desiredEquity, phone]
    );
    res.redirect("/dashboard?investor_requested=1");
  } catch (_) {
    res.redirect("/dashboard");
  }
});

// Helper: get sold equity from investments table
async function getSoldEquity() {
  const r = await db.query("SELECT COALESCE(SUM(equity_percent),0) AS sold FROM investments");
  return parseFloat(r.rows[0].sold) || 0;
}

// GET /investor/offer — approved users view the investment offer
app.get("/investor/offer", ensureInvestorApproved, async (req, res) => {
  try {
    const cfg = await getInvestmentConfig();
    const soldEquity = await getSoldEquity();
    const remainingEquity = parseFloat((cfg.equity - soldEquity).toFixed(2));
    const isFull = remainingEquity <= 0;
    res.render("investor-offer", { cfg, soldEquity, remainingEquity, isFull });
  } catch (_) {
    res.redirect("/dashboard");
  }
});

// POST /api/investor/create-order — create Razorpay order for investment
app.post("/api/investor/create-order", ensureInvestorApproved, async (req, res) => {
  try {
    const cfg = await getInvestmentConfig();
    const soldEquity = await getSoldEquity();
    const remainingEquity = parseFloat((cfg.equity - soldEquity).toFixed(2));
    if (remainingEquity <= 0) return res.json({ success: false, message: "All equity has been sold." });

    const amount = parseFloat(req.body.amount);
    if (!amount || amount < 1250) return res.json({ success: false, message: "Minimum investment is ₹1,250." });

    const equityPercent = parseFloat(((amount / cfg.valuation) * 100).toFixed(2));
    if (equityPercent > remainingEquity) {
      return res.json({ success: false, message: `Only ${remainingEquity.toFixed(2)}% equity remaining (max ₹${Math.floor(remainingEquity / 100 * cfg.valuation).toLocaleString('en-IN')}).` });
    }

    const rzp = getRazorpay();
    const order = await rzp.orders.create({
      amount:   Math.round(amount * 100),
      currency: "INR",
      receipt:  "invest_" + Date.now(),
      notes:    { user_id: req.user.id, type: "investment", equity: equityPercent, valuation: cfg.valuation },
    });
    res.json({ success: true, orderId: order.id, amount: order.amount, currency: "INR", key: process.env.RAZORPAY_KEY_ID, equityPercent, cfg });
  } catch (err) {
    res.status(500).json({ success: false, message: "Could not create order." });
  }
});

// POST /api/investor/verify — verify payment & record investment
app.post("/api/investor/verify", ensureAuthenticated, async (req, res) => {
  if (!req.user) return res.status(401).json({ success: false });
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, amount, equityPercent } = req.body;
  try {
    // Verify signature
    const hmac = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET);
    hmac.update(razorpay_order_id + "|" + razorpay_payment_id);
    if (hmac.digest("hex") !== razorpay_signature) {
      return res.status(400).json({ success: false, message: "Invalid payment signature." });
    }
    // Idempotency check
    const existing = await db.query("SELECT id FROM investments WHERE payment_id=?", [razorpay_payment_id]);
    if (existing.rows.length > 0) return res.json({ success: true });
    // Re-check remaining equity
    const cfg = await getInvestmentConfig();
    const soldEquity = await getSoldEquity();
    const remainingEquity = parseFloat((cfg.equity - soldEquity).toFixed(2));
    const eq = parseFloat(equityPercent) || parseFloat(((parseFloat(amount) / cfg.valuation) * 100).toFixed(2));
    if (eq > remainingEquity + 0.01) {
      return res.status(409).json({ success: false, message: "Not enough equity remaining." });
    }
    // Record investment with actual amount and calculated equity
    const investAmount = parseFloat(amount) || parseFloat(((eq / 100) * cfg.valuation).toFixed(2));
    await db.query(
      `INSERT INTO investments (user_id, amount, equity_percent, valuation, payment_id, razorpay_order_id)
       VALUES (?,?,?,?,?,?)`,
      [req.user.id, investAmount, eq, cfg.valuation, razorpay_payment_id, razorpay_order_id]
    );
    // Update user role
    await db.query("UPDATE users SET role='investor' WHERE id=?", [req.user.id]);
    // Refresh session user
    req.user.role = "investor";
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: "Verification failed." });
  }
});

// GET /investor/dashboard — investor profile card
app.get("/investor/dashboard", ensureInvestor, async (req, res) => {
  try {
    const inv = await db.query(
      `SELECT i.*, u.name, u.email FROM investments i JOIN users u ON u.id=i.user_id WHERE i.user_id=? ORDER BY i.created_at DESC LIMIT 1`,
      [req.user.id]
    );
    const profile = await db.query("SELECT profile_image_url FROM user_profiles WHERE user_id=?", [req.user.id]);
    const investment = inv.rows[0];
    if (!investment) return res.redirect("/investor/offer");
    res.render("investor-dashboard", {
      investment,
      profileImageUrl: profile.rows[0]?.profile_image_url || null,
    });
  } catch (_) {
    res.redirect("/dashboard");
  }
});

// GET /investor/history — investment history
app.get("/investor/history", ensureInvestor, async (req, res) => {
  try {
    const rows = await db.query(
      "SELECT * FROM investments WHERE user_id=? ORDER BY created_at DESC",
      [req.user.id]
    );
    res.render("investor-history", { investments: rows.rows });
  } catch (_) {
    res.redirect("/dashboard");
  }
});

// ── Admin panel ──────────────────────────────────────────────────────────────
app.use("/admin", ensureAdmin, adminRouter(db));

// ── REST: message history for a request ──────────────────────────────────────
app.get("/api/request/:id/messages", ensureAuthenticated, async (req, res) => {
  const requestId = parseInt(req.params.id, 10);
  const userId = req.user.id;
  const isAdmin = req.user.role === "admin";
  try {
    // Verify the user owns this request OR is admin
    if (!isAdmin) {
      const own = await db.query(
        "SELECT id FROM service_requests WHERE id=? AND user_id=?",
        [requestId, userId]
      );
      if (!own.rows.length) return res.status(403).json({ success: false });
    }
    const msgs = await db.query(
      `SELECT m.id, m.sender_id, m.sender_role, m.message, m.is_read, m.created_at,
              u.name AS sender_name
       FROM request_messages m
       LEFT JOIN users u ON u.id = m.sender_id
       WHERE m.request_id = ?
       ORDER BY m.created_at ASC`,
      [requestId]
    );
    // Mark messages as read for this viewer
    const markRole = isAdmin ? "user" : "admin";
    await db.query(
      "UPDATE request_messages SET is_read=true WHERE request_id=? AND sender_role=? AND is_read=false",
      [requestId, markRole]
    );
    return res.json({ success: true, messages: msgs.rows });
  } catch (err) {
    return res.status(500).json({ success: false });
  }
});

// ── Guest chat endpoints (no auth required) ──────────────────────────────────
app.post("/api/guest/start-chat", express.json(), async (req, res) => {
  const name  = (req.body.name  || "").trim().slice(0, 100);
  const email = (req.body.email || "").trim().slice(0, 200);
  if (!name || !email.includes("@")) return res.status(400).json({ success: false, message: "Name and valid email required." });
  try {
    const token = crypto.randomBytes(20).toString("hex");
    const result = await db.query(
      `INSERT INTO service_requests (name, email, service_type, details, guest_token)
       VALUES (?, ?, 'chat', 'Guest chat session', ?)`,
      [name, email, token]
    );
    return res.json({ success: true, requestId: result.insertId, token });
  } catch (err) {
    return res.status(500).json({ success: false });
  }
});

app.post("/api/guest/chat/message", express.json(), async (req, res) => {
  const { requestId, token, message } = req.body;
  const msg = (message || "").toString().trim().slice(0, 2000);
  if (!requestId || !token || !msg) return res.status(400).json({ success: false });
  try {
    const check = await db.query(
      "SELECT id FROM service_requests WHERE id=? AND guest_token=?",
      [requestId, token]
    );
    if (!check.rows.length) return res.status(403).json({ success: false });
    const msgResult = await db.query(
      `INSERT INTO request_messages (request_id, sender_id, sender_role, message)
       VALUES (?, NULL, 'user', ?)`,
      [requestId, msg]
    );
    const newMsg = await db.query("SELECT id, sender_role, message, created_at FROM request_messages WHERE id=?", [msgResult.insertId]);
    const row = { ...newMsg.rows[0], request_id: requestId, sender_name: null };
    // Push to admin in real-time via Socket.io
    io.to(`request-${requestId}`).emit("message", row);
    return res.json({ success: true, id: msgResult.rows[0].id });
  } catch (err) {
    return res.status(500).json({ success: false });
  }
});

app.post("/api/guest/chat/typing", express.json(), async (req, res) => {
  const { requestId, token } = req.body;
  if (!requestId || !token) return res.status(400).json({ success: false });
  try {
    const check = await db.query(
      "SELECT id FROM service_requests WHERE id=? AND guest_token=?",
      [parseInt(requestId, 10), token]
    );
    if (!check.rows.length) return res.status(403).json({ success: false });
    const rid = parseInt(requestId, 10);
    guestTypingStore.set(rid, Date.now());
    setTimeout(() => {
      if (guestTypingStore.get(rid) <= Date.now() - 3800) guestTypingStore.delete(rid);
    }, 4000);
    // Notify admin in real-time
    io.to(`request-${rid}`).emit("user-typing", rid);
    return res.json({ success: true });
  } catch (_) {
    return res.status(500).json({ success: false });
  }
});

app.get("/api/guest/chat/:requestId/messages", async (req, res) => {
  const requestId = parseInt(req.params.requestId, 10);
  const token     = (req.query.token || "").trim();
  if (!requestId || !token) return res.status(400).json({ success: false });
  try {
    const check = await db.query(
      "SELECT id FROM service_requests WHERE id=? AND guest_token=?",
      [requestId, token]
    );
    if (!check.rows.length) return res.status(403).json({ success: false });
    const msgs = await db.query(
      `SELECT m.id, m.sender_role, m.message, m.created_at,
              u.name AS sender_name
       FROM request_messages m
       LEFT JOIN users u ON u.id = m.sender_id
       WHERE m.request_id = ?
       ORDER BY m.created_at ASC`,
      [requestId]
    );
    const lastTyping = adminTypingStore.get(requestId) || 0;
    const adminTyping = (Date.now() - lastTyping) < 3000;
    return res.json({ success: true, messages: msgs.rows, adminTyping });
  } catch (err) {
    return res.status(500).json({ success: false });
  }
});

// ── HTTP server + Socket.io ───────────────────────────────────────────────────
// In-memory typing indicators: requestId → timestamp of last keystroke
const adminTypingStore = new Map();
const guestTypingStore = new Map();

const server = createServer(app);
const io = new SocketServer(server, { cors: { origin: false } });

// Share Express session with Socket.io
io.use((socket, next) => sessionMiddleware(socket.request, {}, next));
io.use((socket, next) => passport.initialize()(socket.request, {}, next));
io.use((socket, next) => passport.session()(socket.request, {}, next));

io.on("connection", (socket) => {
  const user = socket.request.user;
  if (!user) { socket.disconnect(true); return; }

  socket.on("join-request", async (requestId) => {
    const rid = parseInt(requestId, 10);
    if (!rid) return;
    const isAdmin = user.role === "admin";
    if (!isAdmin) {
      // Verify ownership
      try {
        const own = await db.query(
          "SELECT id FROM service_requests WHERE id=? AND user_id=?",
          [rid, user.id]
        );
        if (!own.rows.length) return;
      } catch (_) { return; }
    }
    socket.join(`request-${rid}`);
  });

  socket.on("admin-typing", (requestId) => {
    if (user.role !== "admin") return;
    const rid = parseInt(requestId, 10);
    if (!rid) return;
    adminTypingStore.set(rid, Date.now());
    // Auto-expire after 4s (cleanup)
    setTimeout(() => {
      if (adminTypingStore.get(rid) <= Date.now() - 3800) adminTypingStore.delete(rid);
    }, 4000);
  });

  socket.on("send-message", async ({ requestId, message }) => {
    const rid = parseInt(requestId, 10);
    const msg = (message || "").toString().trim().slice(0, 2000);
    if (!rid || !msg) return;
    const isAdmin = user.role === "admin";
    try {
      // Verify access
      if (!isAdmin) {
        const own = await db.query(
          "SELECT id FROM service_requests WHERE id=? AND user_id=?",
          [rid, user.id]
        );
        if (!own.rows.length) return;
      }
      const result = await db.query(
        `INSERT INTO request_messages (request_id, sender_id, sender_role, message)
         VALUES (?, ?, ?, ?)`,
        [rid, user.id, isAdmin ? "admin" : "user", msg]
      );
      const newMsgRow = await db.query(
        "SELECT id, sender_id, sender_role, message, is_read, created_at FROM request_messages WHERE id=?",
        [result.insertId]
      );
      const row = { ...newMsgRow.rows[0], request_id: rid, sender_name: user.name };
      io.to(`request-${rid}`).emit("message", row);
    } catch (err) {
    }
  });
});

server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// ========== Service Request Routes ==========
app.get("/terms-privacy", (req, res) => {
  res.render("terms-privacy");
});
// Contact page
app.get("/contact", (req, res) => {
  res.render("contact");
});

app.post("/contact", async (req, res) => {
  const { name, email, subject, message } = req.body;
  if (!name || !email || !message) {
    return res.render("contact", { contactError: "Please fill in all required fields." });
  }
  try {
    const transporter = getTransporter();
    await transporter.sendMail({
      from: `"SmrAI-Studio Contact" <${process.env.EMAIL_USER}>`,
      to: "tech@sumarpohz.com",
      replyTo: email,
      subject: `[Contact] ${subject || "General Inquiry"} — from ${name}`,
      html: `
        <div style="font-family:sans-serif;max-width:600px;margin:auto;background:#f9fafb;padding:32px;border-radius:12px;">
          <h2 style="color:#4f46e5;margin-bottom:4px;">New Contact Message</h2>
          <p style="color:#6b7280;margin-top:0;font-size:14px;">via SmrAI-Studio contact form</p>
          <table style="width:100%;border-collapse:collapse;margin:24px 0;">
            <tr><td style="padding:10px 0;color:#374151;font-weight:600;width:120px;">Name</td><td style="padding:10px 0;color:#111827;">${name}</td></tr>
            <tr><td style="padding:10px 0;color:#374151;font-weight:600;">Email</td><td style="padding:10px 0;color:#111827;"><a href="mailto:${email}" style="color:#4f46e5;">${email}</a></td></tr>
            <tr><td style="padding:10px 0;color:#374151;font-weight:600;">Subject</td><td style="padding:10px 0;color:#111827;">${subject || 'General Inquiry'}</td></tr>
          </table>
          <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:20px;">
            <p style="color:#374151;font-size:15px;line-height:1.7;margin:0;">${message.replace(/\n/g, '<br>')}</p>
          </div>
          <p style="color:#9ca3af;font-size:12px;margin-top:24px;">Reply directly to this email to respond to ${name}.</p>
        </div>
      `,
    });
    res.render("contact", { contactSuccess: true });
  } catch (err) {
    console.error("[contact mail error]", err.message);
    res.render("contact", { contactError: "Failed to send message. Please try again or email us directly." });
  }
});

// Support page
app.get("/support", (req, res) => {
  res.render("support");
});

app.post("/support", async (req, res) => {
  const { name, email, subject, message } = req.body;
  if (!name || !email || !message) {
    return res.render("support", { contactError: "Please fill in all required fields." });
  }
  try {
    const transporter = getTransporter();
    await transporter.sendMail({
      from: `"SmrAI-Studio Support" <${process.env.EMAIL_USER}>`,
      to: "tech@sumarpohz.com",
      replyTo: email,
      subject: `[Support] ${subject || "General"} — from ${name}`,
      html: `
        <div style="font-family:sans-serif;max-width:600px;margin:auto;background:#f9fafb;padding:32px;border-radius:12px;">
          <h2 style="color:#4f46e5;margin-bottom:4px;">New Support Ticket</h2>
          <p style="color:#6b7280;margin-top:0;font-size:14px;">via SmrAI-Studio support form</p>
          <table style="width:100%;border-collapse:collapse;margin:24px 0;">
            <tr><td style="padding:10px 0;color:#374151;font-weight:600;width:120px;">Name</td><td style="padding:10px 0;color:#111827;">${name}</td></tr>
            <tr><td style="padding:10px 0;color:#374151;font-weight:600;">Email</td><td style="padding:10px 0;color:#111827;"><a href="mailto:${email}" style="color:#4f46e5;">${email}</a></td></tr>
            <tr><td style="padding:10px 0;color:#374151;font-weight:600;">Issue Type</td><td style="padding:10px 0;color:#111827;">${subject || 'General'}</td></tr>
          </table>
          <div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:20px;">
            <p style="color:#374151;font-size:15px;line-height:1.7;margin:0;">${message.replace(/\n/g, '<br>')}</p>
          </div>
          <p style="color:#9ca3af;font-size:12px;margin-top:24px;">Reply directly to this email to respond to ${name}.</p>
        </div>
      `,
    });
    res.render("support", { contactSuccess: true });
  } catch (err) {
    console.error("[support mail error]", err.message);
    res.render("support", { contactError: "Failed to send. Please email us directly at tech@sumarpohz.com" });
  }
});

// Help Center
app.get("/help", (req, res) => {
  res.render("help");
});

// FAQ
app.get("/faq", (req, res) => {
  res.render("faq");
});
// About Us
app.get("/about", (req, res) => {
  res.render("about");
});

// News
app.get("/news", (req, res) => {
  res.render("news");
});

// Show request form
app.get("/request", (req, res) => {
  res.render("request");
});

// Handle form submission
app.post("/request", async (req, res) => {
  const { name, email, service_type, details } = req.body;
  const userId = req.user?.id ?? null;

  try {
    await db.query(
      "INSERT INTO service_requests (name, email, service_type, details, user_id) VALUES (?, ?, ?, ?, ?)",
      [name, email, service_type, details, userId]
    );

    res.render("request-success");
  } catch (err) {
    res.send("Something went wrong while saving your request. Please try again.");
  }
});
app.post("/profile/update", ensureAuthenticated, async (req, res) => {
  const { name, phone, location } = req.body;

  try {
    // Update users table (name)
    if (name && name.trim() !== "") {
      await db.query("UPDATE users SET name = ? WHERE id = ?", [
        name.trim(),
        req.user.id,
      ]);
    }

    // Upsert into user_profiles
    await db.query(
      `INSERT INTO user_profiles (user_id, full_name, phone, location, updated_at)
       VALUES (?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE
         full_name = VALUES(full_name),
         phone = VALUES(phone),
         location = VALUES(location),
         updated_at = NOW()`,
      [req.user.id, name?.trim() || null, phone || null, location || null]
    );

    // Redirect back to the page we came from (keeps sidebar context)
    const referer = req.get("referer") || "/dashboard";
    res.redirect(referer);
  } catch (err) {
    res.redirect("/dashboard");
  }
});

// Resume-builder photo upload — returns JSON so the page can update without a redirect
// Stores as base64 data URL so images survive Render's ephemeral filesystem restarts
app.post(
  "/resume-builder/upload-photo",
  ensureAuthenticated,
  upload.single("photo"),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ success: false, error: "No file received" });
    }
    const b64 = `data:${req.file.mimetype};base64,${fs.readFileSync(req.file.path).toString("base64")}`;
    try { fs.unlinkSync(req.file.path); } catch(_) {}
    try {
      await db.query(
        `INSERT INTO user_profiles (user_id, profile_image_url, updated_at)
         VALUES (?, ?, NOW())
         ON DUPLICATE KEY UPDATE profile_image_url = VALUES(profile_image_url), updated_at = NOW()`,
        [req.user.id, b64]
      );
    } catch (err) {
      return res.status(500).json({ success: false, error: "DB error" });
    }
    res.json({ success: true, imagePath: b64 });
  }
);

app.post(
  "/profile/photo",
  ensureAuthenticated,
  upload.single("profilePhoto"),
  async (req, res) => {
    if (!req.file) {
      return res.redirect("/dashboard");
    }
    const b64 = `data:${req.file.mimetype};base64,${fs.readFileSync(req.file.path).toString("base64")}`;
    try { fs.unlinkSync(req.file.path); } catch(_) {}
    try {
      await db.query(
        `INSERT INTO user_profiles (user_id, profile_image_url, updated_at)
         VALUES (?, ?, NOW())
         ON DUPLICATE KEY UPDATE profile_image_url = VALUES(profile_image_url), updated_at = NOW()`,
        [req.user.id, b64]
      );
    } catch (err) {}
    const referer = req.get("referer") || "/dashboard";
    res.redirect(referer);
  }
);

// ── Refer & Earn page ────────────────────────────────────────────────────────
app.get("/refer", ensureAuthenticated, async (req, res) => {
  try {
    const uRow = await db.query(
      "SELECT name, email, referral_code, wallet_balance FROM users WHERE id=?",
      [req.user.id]
    );
    const u = uRow.rows[0];
    const baseUrl = await getSiteUrl();
    const referralUrl = `${baseUrl}/register?ref=${u.referral_code}`;

    const qrDataUrl = await QRCode.toDataURL(referralUrl, {
      width: 260, margin: 2, color: { dark: "#0f172a", light: "#ffffff" },
    });

    const stats = await db.query(
      `SELECT COUNT(u2.id) AS invited
       FROM users u2
       WHERE u2.referred_by = ?`,
      [req.user.id]
    );

    const invitedCount = parseInt(stats.rows[0].invited) || 0;

    res.render("refer", {
      user: u,
      referralUrl,
      qrDataUrl,
      walletBalance: parseFloat(u.wallet_balance) || 0,
      invitedCount,
      totalEarned: invitedCount * 20, // fixed ₹20 per referral
    });
  } catch (err) {
    res.redirect("/dashboard");
  }
});

// ── Shared helper: look up original price for a template ────────────────────
async function getTemplatePrice(template) {
  let priceRupees = 100;
  if (template && template.startsWith("adm-")) {
    const tplRow = await db.query(
      "SELECT price_inr, is_paid FROM admin_templates WHERE slug=?", [template]
    );
    if (tplRow.rows[0]) {
      priceRupees = tplRow.rows[0].is_paid ? (tplRow.rows[0].price_inr || 49) : 0;
    }
  } else {
    const category = getTemplateById(template || "modern-1").category || "experienced";
    const priceRes = await db.query(
      "SELECT value FROM admin_settings WHERE `key` = ?", [`price_${category}`]
    );
    if (priceRes.rows.length) priceRupees = parseInt(priceRes.rows[0].value, 10);
  }
  return priceRupees;
}

// ── Coupon validation (public, authenticated) ────────────────────────────────
app.post("/api/coupons/validate", ensureAuthenticated, async (req, res) => {
  try {
    const { code, template } = req.body || {};
    if (!code) return res.status(400).json({ valid: false, message: "No coupon code provided." });

    const upper = String(code).trim().toUpperCase();
    const row = await db.query(
      `SELECT * FROM coupons WHERE code=? AND is_active=true`, [upper]
    );
    if (!row.rows[0]) return res.json({ valid: false, message: "Invalid coupon code." });

    const c = row.rows[0];

    // Expiry check
    if (c.expires_at && new Date(c.expires_at) < new Date()) {
      return res.json({ valid: false, message: "This coupon has expired." });
    }
    // Usage limit check
    if (c.max_uses > 0 && c.uses_count >= c.max_uses) {
      return res.json({ valid: false, message: "This coupon has reached its usage limit." });
    }
    // First-time only check
    if (c.first_time_only) {
      const prior = await db.query(
        "SELECT id FROM payments WHERE user_id=? AND status='captured' LIMIT 1",
        [req.user.id]
      );
      if (prior.rows.length > 0) {
        return res.json({ valid: false, message: "This coupon is for first-time users only." });
      }
    }

    const originalAmount = await getTemplatePrice(template);

    // Min amount check
    if (c.min_amount > 0 && originalAmount < Number(c.min_amount)) {
      return res.json({ valid: false, message: `This coupon requires a minimum order of ₹${c.min_amount}.` });
    }

    let discountAmount = 0;
    if (c.discount_type === "percent") {
      discountAmount = Math.floor(originalAmount * Number(c.discount_value) / 100);
    } else {
      discountAmount = Math.min(Number(c.discount_value), originalAmount);
    }
    const finalAmount = Math.max(0, originalAmount - discountAmount);

    return res.json({
      valid: true,
      code: upper,
      discountType: c.discount_type,
      discountValue: Number(c.discount_value),
      originalAmount,
      discountAmount,
      finalAmount,
      message: `${c.discount_type === "percent" ? c.discount_value + "%" : "₹" + c.discount_value} off applied!`,
    });
  } catch (err) {
    res.status(500).json({ valid: false, message: "Server error. Please try again." });
  }
});

// Create Razorpay order — price read dynamically from admin_settings
app.post("/api/razorpay/create-order", ensureAuthenticated, async (req, res) => {
  try {
    const { template, couponCode, useWallet } = req.body || {};
    const originalPriceRupees = await getTemplatePrice(template);
    let priceRupees = originalPriceRupees;

    // Apply coupon discount if provided
    if (couponCode) {
      const upper = String(couponCode).trim().toUpperCase();
      const row = await db.query(
        `SELECT * FROM coupons WHERE code=? AND is_active=true`, [upper]
      );
      const c = row.rows[0];
      if (c && !(c.expires_at && new Date(c.expires_at) < new Date()) &&
          !(c.max_uses > 0 && c.uses_count >= c.max_uses)) {
        let discount = 0;
        if (c.discount_type === "percent") {
          discount = Math.floor(priceRupees * Number(c.discount_value) / 100);
        } else {
          discount = Math.min(Number(c.discount_value), priceRupees);
        }
        priceRupees = Math.max(0, priceRupees - discount);
      }
    }

    // Auto-apply referral discount (30%) if: user was referred AND has never paid before
    let referralDiscountRupees = 0;
    const userRefRow = await db.query(
      "SELECT referred_by FROM users WHERE id=?", [req.user.id]
    );
    if (userRefRow.rows[0]?.referred_by) {
      const priorPay = await db.query(
        "SELECT id FROM payments WHERE user_id=? AND status='captured' LIMIT 1",
        [req.user.id]
      );
      if (!priorPay.rows.length) {
        referralDiscountRupees = Math.floor(originalPriceRupees * 0.30);
        priceRupees = Math.max(1, priceRupees - referralDiscountRupees);
      }
    }

    // Apply wallet balance if requested
    let walletDeduction = 0;
    if (useWallet) {
      const walletRow = await db.query("SELECT wallet_balance FROM users WHERE id=?", [req.user.id]);
      const walletRs = parseFloat(walletRow.rows[0]?.wallet_balance) || 0;
      walletDeduction = Math.min(walletRs, priceRupees);
      if (walletDeduction >= priceRupees) {
        // Wallet covers full price — skip Razorpay entirely
        return res.json({
          success: true,
          walletOnly: true,
          walletDeduction,
          originalPrice: originalPriceRupees,
          referralDiscount: referralDiscountRupees,
        });
      }
      if (walletDeduction > 0) {
        priceRupees = Math.max(1, priceRupees - walletDeduction);
      }
    }

    const priceInPaise = priceRupees * 100;

    const options = {
      amount: priceInPaise,
      currency: "INR",
      receipt: "resume_" + Date.now(),
      notes: {
        referralDiscount: referralDiscountRupees.toString(),
        walletDeduction: walletDeduction.toString(),
        originalPrice: originalPriceRupees.toString(),
      },
    };

    const order = await getRazorpay().orders.create(options);

    res.json({
      success: true,
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      key: process.env.RAZORPAY_KEY_ID,
      referralDiscount: referralDiscountRupees,
      walletDeduction,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Unable to create order" });
  }
});

// Wallet balance for sidebar
app.get("/api/wallet/balance", ensureAuthenticated, async (req, res) => {
  try {
    const row = await db.query("SELECT wallet_balance FROM users WHERE id=?", [req.user.id]);
    res.json({ success: true, balance: parseFloat(row.rows[0]?.wallet_balance) || 0 });
  } catch (_) { res.json({ success: true, balance: 0 }); }
});

// Wallet-only payment — full amount covered by wallet, no Razorpay
app.post("/api/wallet/pay", ensureAuthenticated, async (req, res) => {
  try {
    const { template, couponCode, resumeId } = req.body || {};
    const userId = req.user.id;

    // Re-calculate price (same logic as create-order)
    const originalPriceRupees = await getTemplatePrice(template);
    let priceRupees = originalPriceRupees;

    // Apply coupon discount if provided
    const appliedCoupon = couponCode ? String(couponCode).trim().toUpperCase() : null;
    if (appliedCoupon) {
      const row = await db.query(`SELECT * FROM coupons WHERE code=? AND is_active=true`, [appliedCoupon]);
      const c = row.rows[0];
      if (c && !(c.expires_at && new Date(c.expires_at) < new Date()) &&
          !(c.max_uses > 0 && c.uses_count >= c.max_uses)) {
        let discount = 0;
        if (c.discount_type === "percent") {
          discount = Math.floor(priceRupees * Number(c.discount_value) / 100);
        } else {
          discount = Math.min(Number(c.discount_value), priceRupees);
        }
        priceRupees = Math.max(0, priceRupees - discount);
      }
    }

    // Auto-apply referral discount (30%) on first payment
    const userRefRow = await db.query("SELECT referred_by FROM users WHERE id=?", [userId]);
    if (userRefRow.rows[0]?.referred_by) {
      const priorPay = await db.query(
        "SELECT id FROM payments WHERE user_id=? AND status='captured' LIMIT 1", [userId]
      );
      if (!priorPay.rows.length) {
        priceRupees = Math.max(1, priceRupees - Math.floor(originalPriceRupees * 0.30));
      }
    }

    // Server-side check: wallet must cover the full price
    const walletRow = await db.query("SELECT wallet_balance FROM users WHERE id=?", [userId]);
    const walletRs = parseFloat(walletRow.rows[0]?.wallet_balance) || 0;
    if (walletRs < priceRupees) {
      return res.status(400).json({ success: false, message: "Insufficient wallet balance" });
    }

    // Deduct from wallet
    await db.query(
      "UPDATE users SET wallet_balance = GREATEST(0, wallet_balance - ?) WHERE id=?",
      [priceRupees, userId]
    );

    // Record payment (no Razorpay columns)
    const paymentInsert = await db.query(
      `INSERT INTO payments (user_id, resume_id, amount, currency, purpose, status, coupon_code)
       VALUES (?, ?, ?, 'INR', 'download', 'captured', ?)`,
      [userId, resumeId || null, priceRupees * 100, appliedCoupon]
    );
    const newPaymentId = paymentInsert.insertId;

    // Record wallet transaction
    await db.query(
      "INSERT INTO wallet_transactions (user_id,amount,type,reason,ref_id) VALUES (?,?,'debit','used_in_payment',?)",
      [userId, priceRupees, newPaymentId]
    ).catch(() => {});

    // Increment coupon uses_count
    if (appliedCoupon) {
      await db.query(
        "UPDATE coupons SET uses_count = uses_count + 1 WHERE code = ?", [appliedCoupon]
      ).catch(() => {});
    }

    // Issue referral reward on first captured payment
    const refRow = await db.query("SELECT referred_by FROM users WHERE id=?", [userId]);
    const referrerId = refRow.rows[0]?.referred_by;
    if (referrerId) {
      const payCount = await db.query(
        "SELECT COUNT(*) AS count FROM payments WHERE user_id=? AND status='captured'", [userId]
      );
      if (parseInt(payCount.rows[0].count) === 1) {
        const reward = 20;
        await db.query(
          "UPDATE users SET wallet_balance = wallet_balance + ? WHERE id=?", [reward, referrerId]
        ).catch(() => {});
        await db.query(
          "INSERT INTO wallet_transactions (user_id,amount,type,reason,ref_id) VALUES (?,?,'credit','referral_reward',?)",
          [referrerId, reward, newPaymentId]
        ).catch(() => {});
        await db.query(
          "UPDATE payments SET referral_reward_issued=true WHERE id=?", [newPaymentId]
        ).catch(() => {});
      }
    }

    // Log event
    await db.query(
      "INSERT INTO resume_events (user_id, resume_id, kind) VALUES (?, ?, 'download')",
      [userId, resumeId || null]
    ).catch(() => {});

    logActivity({ userId, actionType: "payment", metadata: { amount: priceRupees * 100, resumeId: resumeId || null }, ip: req.ip });

    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Wallet payment failed" });
  }
});

app.post("/api/razorpay/verify", async (req, res) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: "Session expired or not authenticated",
    });
  }

  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      purpose,     // 'download' or 'print'
      resumeId,    // can be null/empty
      couponCode,  // optional discount coupon
    } = req.body;

    if (
      !razorpay_order_id ||
      !razorpay_payment_id ||
      !razorpay_signature
    ) {
      return res
        .status(400)
        .json({ success: false, message: "Missing Razorpay payment data" });
    }

    // Verify signature
    const hmac = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET);
    hmac.update(razorpay_order_id + "|" + razorpay_payment_id);
    const generatedSignature = hmac.digest("hex");

    if (generatedSignature !== razorpay_signature) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid payment signature" });
    }

    const userId = req.user.id;
    const amount = 100 * 100; // ₹50 in paise
    const currency = "INR";
    const finalPurpose = purpose || "download";
const existing = await db.query(
  "SELECT id FROM payments WHERE razorpay_payment_id = ?",
  [razorpay_payment_id]
);

if (existing.rows.length > 0) {
  const statusResult = await db.query(
    "SELECT status FROM payments WHERE razorpay_payment_id = ?",
    [razorpay_payment_id]
  );

  return res.json({
    success: statusResult.rows[0].status === "captured",
    status: statusResult.rows[0].status,
  });
}


    // Store payment
    const appliedCoupon = couponCode ? String(couponCode).trim().toUpperCase() : null;
    const walletUsed = parseFloat(req.body.walletDeduction) || 0;
    const paymentInsert = await db.query(
      `INSERT INTO payments
       (user_id, resume_id, amount, currency, purpose,
        razorpay_order_id, razorpay_payment_id, razorpay_signature, status, coupon_code)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'captured', ?)`,
      [
        userId,
        resumeId || null,
        amount,
        currency,
        finalPurpose,
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature,
        appliedCoupon,
      ]
    );
    const newPaymentId = paymentInsert.insertId;

    // Increment coupon uses_count if a coupon was applied
    if (appliedCoupon) {
      await db.query(
        "UPDATE coupons SET uses_count = uses_count + 1 WHERE code = ?",
        [appliedCoupon]
      ).catch(() => {});
    }

    // Deduct wallet balance if it was used
    if (walletUsed > 0) {
      await db.query(
        "UPDATE users SET wallet_balance = GREATEST(0, wallet_balance - ?) WHERE id=?",
        [walletUsed, userId]
      ).catch(() => {});
      await db.query(
        "INSERT INTO wallet_transactions (user_id,amount,type,reason,ref_id) VALUES (?,?,'debit','used_in_payment',?)",
        [userId, walletUsed, newPaymentId]
      ).catch(() => {});
    }

    // Issue referral reward to referrer on referee's first payment
    const refRow = await db.query("SELECT referred_by FROM users WHERE id=?", [userId]);
    const referrerId = refRow.rows[0]?.referred_by;
    if (referrerId) {
      const payCount = await db.query(
        "SELECT COUNT(*) AS count FROM payments WHERE user_id=? AND status='captured'",
        [userId]
      );
      if (parseInt(payCount.rows[0].count) === 1) {
        const reward = 20; // fixed ₹20 per successful referral
        await db.query(
          "UPDATE users SET wallet_balance = wallet_balance + ? WHERE id=?",
          [reward, referrerId]
        ).catch(() => {});
        await db.query(
          "INSERT INTO wallet_transactions (user_id,amount,type,reason,ref_id) VALUES (?,?,'credit','referral_reward',?)",
          [referrerId, reward, newPaymentId]
        ).catch(() => {});
        await db.query(
          "UPDATE payments SET referral_reward_issued=true WHERE id=?",
          [newPaymentId]
        ).catch(() => {});
      }
    }

    // Also log an event (for counter stats)
    await db.query(
      `INSERT INTO resume_events (user_id, resume_id, kind)
       VALUES (?, ?, ?)`,
      [userId, resumeId || null, finalPurpose]
    );

    logActivity({ userId, actionType: "payment", metadata: { amount, resumeId: resumeId || null }, ip: req.ip });

    return res.json({ success: true });
  } catch (err) {
    return res
      .status(500)
      .json({ success: false, message: "Payment verification failed" });
  }
});



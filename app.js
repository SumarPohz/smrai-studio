import express from "express";
import pg from "pg";
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
import connectPgSimple from "connect-pg-simple"; 
import dotenv from "dotenv";
import { TEMPLATES, getTemplateById } from "./config/templates-config.js";
import { getFieldsForTemplate, isPhotoTemplate } from "./config/template-fields.js";
import adminRouter from "./routes/admin.js";

const PgSession = connectPgSimple(session);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

if (process.env.NODE_ENV !== "production") {
  dotenv.config();
}

// ----- Razorpay setup (needed for payments) -----
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});
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
    console.warn("⚠️ Vertex AI: no credentials found — AI Suggest will be disabled");
  }

  const vertexAI = new VertexAI(vertexOpts);
  geminiModel = vertexAI.getGenerativeModel({ model: "gemini-2.0-flash" });
} catch (err) {
  console.error("❌ Vertex AI initialisation failed — AI Suggest disabled:", err.message);
}
// Optional: helpful warning in dev
if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
  console.warn("⚠️ RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET missing in .env. Payment routes will fail.");
}

const app = express();
// ---------- PostgreSQL ----------
const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
});

async function initDb() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS service_requests (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        service_type VARCHAR(100) NOT NULL,
        details TEXT,
        status VARCHAR(50) DEFAULT 'new',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await db.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) UNIQUE NOT NULL,
    password TEXT,
    google_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
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
    profile_image_url TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`);

await db.query(`
  CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    otp_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`);

    /* resumes main table */
    await db.query(`
      CREATE TABLE IF NOT EXISTS resumes (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL DEFAULT 'Untitled Resume',
        template VARCHAR(100) NOT NULL DEFAULT 'modern-1',
        data JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    /* experience_level column (safe to run on every startup) */
    await db.query(`
      ALTER TABLE resumes
      ADD COLUMN IF NOT EXISTS experience_level TEXT DEFAULT 'experienced';
    `);

    /* download/print events (for stats) */
    await db.query(`
      CREATE TABLE IF NOT EXISTS resume_events (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        resume_id INTEGER REFERENCES resumes(id) ON DELETE CASCADE,
        kind VARCHAR(50) NOT NULL, -- 'download' or 'print'
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    /* payment history (Razorpay) */
    await db.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
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
      );
    `);

    /* ── Admin: role column on users ── */
    await db.query(`
      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user';
    `);

    /* ── Activity logs table ── */
    await db.query(`
      CREATE TABLE IF NOT EXISTS activity_logs (
        id           SERIAL PRIMARY KEY,
        user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
        action_type  VARCHAR(50) NOT NULL,
        route        VARCHAR(255),
        metadata     JSONB,
        ip_address   VARCHAR(45),
        created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    await db.query(`CREATE INDEX IF NOT EXISTS idx_activity_logs_created ON activity_logs(created_at DESC);`);
    await db.query(`CREATE INDEX IF NOT EXISTS idx_activity_logs_user ON activity_logs(user_id);`);

    console.log("✅ Tables ready: service_requests, resumes, resume_events, payments, activity_logs");
  } catch (err) {
    console.error("❌ Error initializing DB:", err);
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
        console.error("❌ Razorpay webhook signature mismatch");
        return res.status(400).send("Invalid signature");
      }

      const event = JSON.parse(req.body.toString());
      if (event.event === "payment.captured") {
        const payment = event.payload.payment.entity;
        await db.query(
          `
          INSERT INTO payments (razorpay_payment_id, status, amount, currency)
          VALUES ($1, 'captured', $2, $3)
          ON CONFLICT (razorpay_payment_id)
          DO UPDATE SET status = 'captured'
          `,
          [payment.id, payment.amount, payment.currency]
        );

      }

      if (event.event === "payment.failed") {
        const payment = event.payload.payment.entity;

        await db.query(
          `
          INSERT INTO payments (razorpay_payment_id, status, amount, currency)
          VALUES ($1, 'failed', $2, $3)
          ON CONFLICT (razorpay_payment_id)
          DO UPDATE SET status = 'failed'
          `,
          [payment.id, payment.amount, payment.currency]
        );
      }

      return res.json({ received: true });
    } catch (err) {
      console.error("Webhook error:", err);
      return res.status(500).send("Webhook error");
    }
  }
);


(async () => {
  await initDb();
})();

/* ✅ THEN body parsers */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

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

app.use(
  session({
    store: new PgSession({
      pool: db,
      tableName: "session",
      createTableIfMissing: true,
    }),
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
  })
);

app.use(passport.initialize());
app.use(passport.session());

// ---------- Passport Local Strategy ----------
passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
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

        let result = await db.query("SELECT * FROM users WHERE google_id = $1", [
          googleId,
        ]);

        if (result.rows.length === 0) {
          result = await db.query(
            "INSERT INTO users (email, google_id, name) VALUES ($1, $2, $3) RETURNING *",
            [email, googleId, name]
          );
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
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    // Pass false (not undefined) when user not found — Passport clears the stale
    // session cookie silently instead of logging "Failed to deserialize user".
    done(null, result.rows[0] || false);
  } catch (err) {
    done(err, null);
  }
});

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false, // true for 465, false for 587
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

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
        "SELECT * FROM user_profiles WHERE user_id = $1",
        [req.user.id]
      );
      if (profileResult.rows.length > 0) {
        res.locals.userProfile = profileResult.rows[0];
      }
    } catch (err) {
      console.error("Error loading user profile:", err);
    }
  }

  next();
});

// ---------- Routes ----------

// Home: your AI services landing page
app.get("/", (req, res) => {
  res.render("home");
});

// Register
app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const check = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (check.rows.length > 0) {
  return res.render("already-registered");
}
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const result = await db.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
      [name, email, hashedPassword]
    );

    const user = result.rows[0];
    req.login(user, (err) => {
      if (err) {
        return res.redirect("/login");
      }
      res.redirect("/dashboard");
    });
  } catch (err) {
    console.error(err);
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
      console.error("Login error:", err);
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
        console.error("Error in req.logIn:", err);
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
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);

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
      "INSERT INTO password_reset_tokens (user_id, otp_hash, expires_at) VALUES ($1, $2, $3)",
      [user.id, otpHash, expiresAt]
    );

    // Send OTP email
    await transporter.sendMail({
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
    console.error("Error in /forgot-password:", err);
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
    const userResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

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
       WHERE user_id = $1 AND used = FALSE 
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

    await db.query("UPDATE users SET password = $1 WHERE id = $2", [
      hashedPassword,
      user.id,
    ]);

    await db.query("UPDATE password_reset_tokens SET used = TRUE WHERE id = $1", [
      token.id,
    ]);

    return res.render("reset-password", {
      error: null,
      message: "Password updated successfully. You can now log in.",
      emailPrefill: "",
    });
  } catch (err) {
    console.error("Error in /reset-password:", err);
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
      profileImageUrl,
      summary,
      experience,
      experienceJson,
      education,
      skills,
      languages,
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
      profileImageUrl,
      summary,
      experience: experienceData,
      education,
      skills,
      languages,
    };

    let savedId;

    if (resumeId) {
      const result = await db.query(
        `UPDATE resumes
         SET title = $1,
             template = $2,
             data = $3,
             experience_level = $4,
             updated_at = NOW()
         WHERE id = $5 AND user_id = $6
         RETURNING id`,
        [title || "Untitled Resume", template || "modern-1", data, experienceLevel || "experienced", resumeId, userId]
      );

      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({ success: false, error: "Resume not found." });
      }

      savedId = result.rows[0].id;
    } else {
      const result = await db.query(
        `INSERT INTO resumes (user_id, title, template, data, experience_level)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id`,
        [userId, title || "Untitled Resume", template || "modern-1", data, experienceLevel || "experienced"]
      );

      savedId = result.rows[0].id;
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
    console.error("Error saving resume:", err);
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
      "DELETE FROM resumes WHERE id = $1 AND user_id = $2",
      [resumeId, userId]
    );
    // Clear session if the deleted resume was the active one
    if (req.session.currentResumeId == resumeId) {
      delete req.session.currentResumeId;
      delete req.session.resumeDraft;
    }
  } catch (err) {
    console.error("Error deleting resume:", err);
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
        "SELECT * FROM resumes WHERE id = $1 AND user_id = $2",
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
      console.error("Error loading resume for edit:", err);
    }
  } else if (req.query.template) {
    const tpl = getTemplateById(req.query.template);
    template = tpl.isAvailable ? tpl.id : "modern-1";
    req.session.lastTemplate = template;
  } else if (req.session?.lastTemplate) {
    template = req.session.lastTemplate;
  } else {
    req.session.lastTemplate = template;
  }

  res.render("resume-builder", {
    profile,
    template,
    draft,
    isPhotoTpl: isPhotoTemplate(template),
    currentUser: req.user,
    user: req.user,
    resumeId: req.session.currentResumeId || null,
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
       WHERE r.user_id = $1
       ORDER BY r.updated_at DESC`,
      [userId]
    );

    res.render("resumes-list", {
      currentUser: req.user,
      resumes: result.rows,
    });
  } catch (err) {
    console.error("Error loading resumes list:", err);
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
      WHERE p.user_id = $1
      ORDER BY p.created_at DESC
      `,
      [userId]
    );

    res.render("payments-list", {
      currentUser: req.user,
      payments: result.rows,
    });
  } catch (err) {
    console.error("Error loading payments list:", err);
    next(err);
  }
});


// Template Fields API – used by AI Interview to know which questions to ask
app.get("/api/template-fields/:templateId", ensureAuthenticated, (req, res) => {
  const fields = getFieldsForTemplate(req.params.templateId);
  res.json({ success: true, fields });
});

app.get("/resume-templates", ensureAuthenticated, (req, res) => {
  res.render("resume-templates", { RESUME_TEMPLATES: TEMPLATES });
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
  const template = getTemplateById(rawTemplate).id;

  try {
    // upsert profile
    await db.query(
      `INSERT INTO user_profiles
        (user_id, full_name, role_title, location, phone, email, summary,
         experience, education, languages, skills, profile_image_url, updated_at)
       VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, NOW())
       ON CONFLICT (user_id)
       DO UPDATE SET
        full_name=$2,
        role_title=$3,
        location=$4,
        phone=$5,
        email=$6,
        summary=$7,
        experience=$8,
        education=$9,
        languages=$10,
        skills=$11,
        profile_image_url=$12,
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

    res.render("resume-preview", { data, template });
  } catch (err) {
    console.error("Error saving profile:", err);
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
     WHERE user_id = $1
       AND resume_id = $2
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
  if (profileImageUrl && typeof profileImageUrl === "string" && profileImageUrl.startsWith("/uploads/")) {
    const imgPath = path.join(__dirname, "public", profileImageUrl);
    if (fs.existsSync(imgPath)) {
      try {
        const photoSize = 72;
        const photoX = (doc.page.width - photoSize) / 2;
        doc.image(imgPath, photoX, margin, { width: photoSize, height: photoSize });
        doc.y = margin + photoSize + 10;
      } catch (_) { /* skip if image unreadable */ }
    }
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

// ── Auth guards ─────────────────────────────────────────────────────────────
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  req.session.returnTo = req.originalUrl;
  req.session.save(() => res.redirect("/login"));
}

function ensureAdmin(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect("/login");
  if (req.user.role === "admin") return next();
  res.status(403).render("403");
}

// ── Activity logger (non-critical — never crashes a request) ─────────────────
async function logActivity({ userId = null, actionType, route = null, metadata = null, ip = null } = {}) {
  try {
    await db.query(
      `INSERT INTO activity_logs (user_id, action_type, route, metadata, ip_address)
       VALUES ($1, $2, $3, $4, $5)`,
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
    const uid = req.user?.id ?? "guest";
    const key = `${uid}:${req.path}`;
    const last = visitCache.get(key) ?? 0;
    const now  = Date.now();
    if (now - last > 5 * 60 * 1000) {   // 5-minute cooldown
      visitCache.set(key, now);
      logActivity({ userId: req.user?.id ?? null, actionType: "visit", route: req.path, ip: req.ip });
    }
  }
  next();
});

app.get("/dashboard", ensureAuthenticated, (req, res) => {
  res.render("dashboard");
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
       VALUES ($1, $2, $3)`,
      [userId, resumeId || null, kind]
    );

    logActivity({ userId, actionType: "download_" + kind, metadata: { resumeId: resumeId || null } });

    return res.json({ success: true });
  } catch (err) {
    console.error("Error logging resume event:", err);
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
        console.error("AI suggest error (experience/empty):", err);
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
      console.error("AI suggest error (experience):", err);
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
    console.error("AI suggest error:", err);

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
    console.error("AI suggest-application error:", err);
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
      console.error("Failed to parse Gemini JSON:", raw);
      return res.status(500).json({ success: false, error: "Failed to parse AI response as JSON" });
    }

    return res.json({ success: true, data: resumeData });
  } catch (err) {
    console.error("AI interview-generate error:", err);
    const errMsg = err.message || "";
    if (errMsg.includes("RESOURCE_EXHAUSTED") || errMsg.includes("429") || errMsg.includes("quota")) {
      return res.json({ success: false, error: "insufficient_quota" });
    }
    return res.json({ success: false, error: "AI error: " + (err.message || "Unknown error") });
  }
});


// ── Admin panel ──────────────────────────────────────────────────────────────
app.use("/admin", ensureAdmin, adminRouter(db));

app.listen(port, () => {
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

// Support page
app.get("/support", (req, res) => {
  res.render("support");
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

  try {
    await db.query(
      "INSERT INTO service_requests (name, email, service_type, details) VALUES ($1, $2, $3, $4)",
      [name, email, service_type, details]
    );

    res.render("request-success");
  } catch (err) {
    console.error("Error saving request:", err);
    res.send("Something went wrong while saving your request. Please try again.");
  }
});
app.post("/profile/update", ensureAuthenticated, async (req, res) => {
  const { name, phone, location } = req.body;

  try {
    // Update users table (name)
    if (name && name.trim() !== "") {
      await db.query("UPDATE users SET name = $1 WHERE id = $2", [
        name.trim(),
        req.user.id,
      ]);
    }

    // Upsert into user_profiles
    await db.query(
      `INSERT INTO user_profiles (user_id, full_name, phone, location, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (user_id)
       DO UPDATE SET
         full_name = $2,
         phone = $3,
         location = $4,
         updated_at = NOW()`,
      [req.user.id, name?.trim() || null, phone || null, location || null]
    );

    // Redirect back to the page we came from (keeps sidebar context)
    const referer = req.get("referer") || "/dashboard";
    res.redirect(referer);
  } catch (err) {
    console.error("Error updating profile:", err);
    res.redirect("/dashboard");
  }
});

// Resume-builder photo upload — returns JSON so the page can update without a redirect
app.post(
  "/resume-builder/upload-photo",
  ensureAuthenticated,
  upload.single("photo"),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ success: false, error: "No file received" });
    }
    const imagePath = "/uploads/" + req.file.filename;
    try {
      await db.query(
        `INSERT INTO user_profiles (user_id, profile_image_url, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (user_id)
         DO UPDATE SET profile_image_url = $2, updated_at = NOW()`,
        [req.user.id, imagePath]
      );
    } catch (err) {
      console.error("Error saving builder photo:", err);
    }
    res.json({ success: true, imagePath });
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

    // This is the path the browser will use (because "public" is the static root)
    const imagePath = "/uploads/" + req.file.filename;

    try {
      await db.query(
        `INSERT INTO user_profiles (user_id, profile_image_url, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (user_id)
         DO UPDATE SET profile_image_url = $2, updated_at = NOW()`,
        [req.user.id, imagePath]
      );
    } catch (err) {
      console.error("Error saving profile photo:", err);
    }

    // 👇 go back to the page the user was on (dashboard or resume-builder)
    const referer = req.get("referer") || "/dashboard";
    res.redirect(referer);
  }
);

// Create Razorpay order for ₹29 (modern-1 download/print)
app.post("/api/razorpay/create-order", ensureAuthenticated, async (req, res) => {
  try {
    const options = {
      amount: 100 * 100,          // ₹50 in paise
      currency: "INR",
      receipt: "resume_" + Date.now(),
    };

    const order = await razorpay.orders.create(options);

    res.json({
      success: true,
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      key: process.env.RAZORPAY_KEY_ID, // used by frontend
    });
  } catch (err) {
    console.error("Razorpay order error:", err);
    res.status(500).json({ success: false, message: "Unable to create order" });
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
      purpose,    // 'download' or 'print'
      resumeId,   // can be null/empty
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
      console.error("Razorpay signature mismatch");
      return res
        .status(400)
        .json({ success: false, message: "Invalid payment signature" });
    }

    const userId = req.user.id;
    const amount = 100 * 100; // ₹50 in paise
    const currency = "INR";
    const finalPurpose = purpose || "download";
const existing = await db.query(
  "SELECT id FROM payments WHERE razorpay_payment_id = $1",
  [razorpay_payment_id]
);

if (existing.rows.length > 0) {
  const statusResult = await db.query(
    "SELECT status FROM payments WHERE razorpay_payment_id = $1",
    [razorpay_payment_id]
  );

  return res.json({
    success: statusResult.rows[0].status === "captured",
    status: statusResult.rows[0].status,
  });
}


    // Store payment
    await db.query(
      `INSERT INTO payments
       (user_id, resume_id, amount, currency, purpose,
        razorpay_order_id, razorpay_payment_id, razorpay_signature, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'captured')`,
      [
        userId,
        resumeId || null,
        amount,
        currency,
        finalPurpose,
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature,
      ]
    );

    // Also log an event (for counter stats)
    await db.query(
      `INSERT INTO resume_events (user_id, resume_id, kind)
       VALUES ($1, $2, $3)`,
      [userId, resumeId || null, finalPurpose]
    );

    logActivity({ userId, actionType: "payment", metadata: { amount, resumeId: resumeId || null }, ip: req.ip });

    return res.json({ success: true });
  } catch (err) {
    console.error("Razorpay verify error:", err);
    return res
      .status(500)
      .json({ success: false, message: "Payment verification failed" });
  }
});

db.on("connect", () => {
  console.log("✅ PostgreSQL connected");
});

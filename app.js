import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import nodemailer from "nodemailer";
import PDFDocument from "pdfkit";
import fs from "fs";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import Razorpay from "razorpay";
import crypto from "crypto";
import OpenAI from "openai";   

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

env.config();

// ----- Razorpay setup (needed for payments) -----
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});
// ----- OpenAI setup (optional, for AI content suggestions) -----
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});
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

    console.log("✅ Tables ready: service_requests, resumes, resume_events, payments");
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

        console.log("✅ Payment captured via webhook:", payment.id);
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

app.set("trust proxy", 1);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: isProd,                  // ✅ HTTPS only in prod
      sameSite: isProd ? "none" : "lax",// ✅ FIX: localhost vs prod
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
    done(null, result.rows[0]);
  } catch (err) {
    done(err, null);
  }
});

// ---------- Middleware to inject user into views ----------
app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
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
        console.log(err);
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

    req.logIn(user, (err) => {
      if (err) {
        console.error("Error in req.logIn:", err);
        return next(err);
      }
      return res.redirect("/dashboard");
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

    // log once to confirm we’re actually receiving data
    console.log("SAVE RESUME BODY:", body);

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
      education,
      skills,
      languages,
    } = body;

    const data = {
      fullName,
      roleTitle,
      email,
      phone,
      location,
      profileImageUrl,
      summary,
      experience,
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
             updated_at = NOW()
         WHERE id = $4 AND user_id = $5
         RETURNING id`,
        [title || "Untitled Resume", template || "modern-1", data, resumeId, userId]
      );

      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({ success: false, error: "Resume not found." });
      }

      savedId = result.rows[0].id;
    } else {
      const result = await db.query(
        `INSERT INTO resumes (user_id, title, template, data)
         VALUES ($1, $2, $3, $4)
         RETURNING id`,
        [userId, title || "Untitled Resume", template || "modern-1", data]
      );

      savedId = result.rows[0].id;
    }

    req.session.currentResumeId = savedId;
    req.session.resumeDraft = data;

    return res.json({ success: true, resumeId: savedId });
  } catch (err) {
    console.error("Error saving resume:", err);
    return res
      .status(500)
      .json({ success: false, error: "Failed to save resume." });
  }
});


// Show resume builder form
app.get("/resume-builder", ensureAuthenticated, (req, res) => {
  const profile = res.locals.userProfile || {};
  const draft = req.session?.resumeDraft || {};

  // Decide which template to use
  let template = "modern-1";

  if (req.query.template) {
    template = req.query.template;
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
    currentUser: req.user,   // used by header
    user: req.user,          // used in this EJS for email fallback
    resumeId: req.session.currentResumeId || null, // safe even if undefined
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


const RESUME_TEMPLATES = [
  {
    id: "modern-1",
    name: "Modern Professional",
    description: "Bold left sidebar with clean typography.",
    badge: "Popular",
  },
  {
    id: "modern-2",
    name: "Modern Contrast",
    description: "Alternative modern layout (you can wire this later).",
    badge: "New",
  },
  {
    id: "minimal-1",
    name: "Minimal Clean",
    description: "Simple, ATS-friendly layout.",
    badge: "ATS Friendly",
  },
];

app.get("/resume-templates", ensureAuthenticated, (req, res) => {
  const RESUME_TEMPLATES = [
    {
      id: "modern-1",
      title: "Modern Professional",
      description: "Clean two-column layout, great for experienced professionals.",
      previewClass: "template-1",
      available: true,
      paid: true,
    },
    { id: "minimal-1", title: "Simple & Minimal", description: "Single-column layout, perfect for freshers and minimalist profiles.", previewClass: "template-3", available: false },
    // Add others as needed
  ];

  res.render("resume-templates", { RESUME_TEMPLATES });
});

// Show preview after form submit
app.post("/resume-builder/preview", ensureAuthenticated, async (req, res) => {
  const data = req.body;
  const template = data.template || req.session?.lastTemplate || "modern-1";

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
    education,
    skills,
  } = req.body;

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

  /* ✅ PAYMENT CONFIRMED → GENERATE PDF */
  const doc = new PDFDocument({ margin: 50 });

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader(
    "Content-Disposition",
    'attachment; filename="SmrAI-Studio-Resume.pdf"'
  );

  doc.pipe(res);

  doc.fontSize(22).text(fullName || "", { align: "center" });
  doc.moveDown(0.5);

  const contactLine = `${email || ""} | ${phone || ""}`;
  doc.fontSize(10).text(contactLine, { align: "center" });

  doc.moveDown(1);
  doc.fontSize(14).text("Summary");
  doc.fontSize(11).text(summary || "");

  doc.moveDown(0.8);
  doc.fontSize(14).text("Experience");
  doc.fontSize(11).text(experience || "");

  doc.moveDown(0.8);
  doc.fontSize(14).text("Education");
  doc.fontSize(11).text(education || "");

  doc.moveDown(0.8);
  doc.fontSize(14).text("Skills");
  doc.fontSize(11).text(skills || "");

  doc.end();
});



// Google Auth
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["email", "profile"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  })
);

// Dashboard (protected)
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

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


    return res.json({ success: true });
  } catch (err) {
    console.error("Error logging resume event:", err);
    return res.status(500).json({ success: false });
  }
});
// ---------- AI Resume Suggestion Route ----------
app.post("/api/ai/suggest", ensureAuthenticated, async (req, res) => {
  const { field, currentText, roleTitle } = req.body || {};

  if (!field) {
    return res.status(400).json({ success: false, message: "field is required" });
  }

  // Build field-specific instructions
  let fieldInstructions = "";

  switch (field) {
    case "summary":
      fieldInstructions = `
        You are writing a professional resume SUMMARY.
        Role: ${roleTitle || "Not specified"}.
        Current text (if any): """${currentText || ""}"""
        Improve or extend this into a crisp 3–5 line professional summary.
        Focus on achievements, strengths, and domain expertise.
        Do not use "I". Write in a neutral tone (e.g. "Results-driven professional...").
        Return plain text only, with line breaks, no bullets or numbering.
      `;
      break;

    case "experience":
      fieldInstructions = `
        You are writing the EXPERIENCE section of a resume.
        Role: ${roleTitle || "Not specified"}.
        Current text (if any): """${currentText || ""}"""
        Convert this into strong, action-based statements suitable for experience.
        Use one responsibility/achievement per line.
        Keep it concise but impactful (4–8 lines).
        Return plain text only, one statement per line, no bullet symbols.
      `;
      break;

    case "education":
      fieldInstructions = `
        You are writing the EDUCATION section of a resume.
        Current text (if any): """${currentText || ""}"""
        Format it as clean lines like:
        "2018 – B.Com, XYZ College, Bangalore"
        "2016 – Higher Secondary, ABC School"
        One entry per line, most recent first.
        Return plain text only, one entry per line.
      `;
      break;

    case "skills":
      fieldInstructions = `
        You are writing the SKILLS section of a resume.
        Role: ${roleTitle || "Not specified"}.
        Current text (if any): """${currentText || ""}"""
        Create a list of 6–12 key skills relevant for this role.
        One skill per line, short phrases, no bullet symbols.
        Mix soft skills and hard skills if appropriate.
        Return plain text only, one skill per line.
      `;
      break;

    case "languages":
      fieldInstructions = `
        You are writing the LANGUAGES section of a resume.
        Current text (if any): """${currentText || ""}"""
        List languages in the format:
        "English – Read, Write, Speak"
        "Hindi – Read, Speak"
        One language per line.
        Return plain text only.
      `;
      break;

    default:
      fieldInstructions = `
        You are helping complete a resume field: ${field}.
        Current text (if any): """${currentText || ""}"""
        Improve or extend this text to look professional and concise.
        Return plain text only, suitable for a resume.
      `;
      break;
  }

  try {
    const response = await openai.responses.create({
      model: "gpt-5.1-mini",
      instructions: "You are a helpful resume-writing assistant.",
      input: fieldInstructions,
    });

    const suggestion = response.output_text || "";
    return res.json({ success: true, text: suggestion.trim() });
  } catch (err) {
    console.error("AI suggest error:", err?.response?.data || err);

    // Special handling for quota / 429
    if (err.code === "insufficient_quota" || err.status === 429) {
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


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// ========== Service Request Routes ==========

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
      amount: 49 * 100,          // ₹49 in paise
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

app.post("/api/razorpay/verify", ensureAuthenticated, async (req, res) => {
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
    const amount = 49 * 100; // ₹49 in paise
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
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')`,
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

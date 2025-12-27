const path = require("path");
const express = require("express");
const bcrypt = require("bcrypt");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const GoogleStrategy = require("passport-google-oauth2").Strategy;
const session = require("express-session");
const nodemailer = require("nodemailer");
const fs = require("fs");
const multer = require("multer");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const dotenv = require("dotenv");
const db = require("./db");

// Hostinger injects env OUTSIDE public_html
const hostingerEnvPath = path.join(
  process.cwd(),
  ".builds",
  "config",
  ".env"
);

if (fs.existsSync(hostingerEnvPath)) {
  dotenv.config({ path: hostingerEnvPath });
  console.log("✅ Loaded Hostinger .env from", hostingerEnvPath);
} else {
  console.warn("❌ Hostinger .env NOT found at", hostingerEnvPath);
}
// ----- Razorpay setup (optional, for payments) -----
let razorpay = null;

if (process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET) {
  razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
  });
  console.log("✅ Razorpay initialized");
} else {
  console.warn(
    "⚠️ RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET missing in env. Payment routes will be disabled."
  );
}

const app = express();
app.set("trust proxy", 1); // ✅ REQUIRED for Hostinger

const port = process.env.PORT || 3000;

const saltRounds = 10;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Razorpay webhook MUST come before body parsers
app.post(
  "/webhook/razorpay",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const signature = req.headers["x-razorpay-signature"];
      const secret = process.env.RAZORPAY_WEBHOOK_SECRET;

      const expected = crypto
        .createHmac("sha256", secret)
        .update(req.body)
        .digest("hex");

      if (expected !== signature) {
        console.error("❌ Razorpay webhook signature mismatch");
        return res.status(400).send("Invalid signature");
      }

      const event = JSON.parse(req.body.toString());

      if (event.event === "payment.captured") {
        const payment = event.payload.payment.entity;

        await db.query(
          `UPDATE payments
           SET status = 'captured'
           WHERE razorpay_payment_id = ?`,
          [payment.id]
        );

        console.log("✅ Payment captured via webhook:", payment.id);
      }

      res.json({ received: true });
    } catch (err) {
      console.error("Webhook error:", err);
      res.status(500).send("Webhook error");
    }
  }
);

// Static files
app.use(express.static(path.join(__dirname, "public")));
const uploadDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log("✅ public/uploads folder created");
}

app.get("/env-test", (req, res) => {
res.json({
mysqlHostDefined: !!process.env.MYSQL_HOST,
mysqlUserDefined: !!process.env.MYSQL_USER,
mysqlDbDefined: !!process.env.MYSQL_DATABASE,
testVar: process.env.TEST_VAR || null,
nodeEnv: process.env.NODE_ENV || null,
port: process.env.PORT || null,
});
});
// Create "public/uploads" if it doesn't exist
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const userId = req.user?.id || "guest";
    const ext = path.extname(file.originalname) || ".jpg";
    cb(null, `user-${userId}-${Date.now()}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: {
    fileSize: 2 * 1024 * 1024, // 2MB
  },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only image files allowed"), false);
    }
    cb(null, true);
  },
});


// ---------- View Engine & Static ----------
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));


// ---------- Session ----------
const isProd = process.env.NODE_ENV === "production";

app.use(
  session({
    name: "smrai.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: isProd,                 // true on HTTPS
      sameSite: isProd ? "none" : "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);


app.use(passport.initialize());
app.use(passport.session());
// ---------- Passport Local ----------
passport.use(
  new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = ?", [email]);
      if (result.rows.length === 0)
        return done(null, false, { message: "No user with that email" });

      const user = result.rows[0];
      if (!user.password)
        return done(null, false, { message: "Use Google login" });

      const match = await bcrypt.compare(password, user.password);
      if (!match)
        return done(null, false, { message: "Incorrect password" });

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

// ---------- Google OAuth ----------
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    "google",
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback",
      },
      async (_req, _a, _r, profile, done) => {
        try {
          const email = profile.email;
          let result = await db.query(
            "SELECT * FROM users WHERE google_id = ? OR email = ?",
            [profile.id, email]
          );

          if (result.rows.length === 0) {
            const insert = await db.query(
              "INSERT INTO users (email, google_id, name) VALUES (?, ?, ?)",
              [email, profile.id, profile.displayName]
            );
            result = await db.query("SELECT * FROM users WHERE id = ?", [
              insert.insertId,
            ]);
          }

          return done(null, result.rows[0]);
        } catch (err) {
          return done(err);
        }
      }
    )
  );
}

// ---------- Serialize / Deserialize ----------
passport.serializeUser((user, done) => {
 done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
 try {
 const result = await db.query("SELECT * FROM users WHERE id = ?", [id]);
 const user = result.rows[0] || null; // ensure null if not found
 done(null, user);
 } catch (err) {
 done(err, null);
 }
});

// ---------- Auth helper ----------
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

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
        "SELECT * FROM user_profiles WHERE user_id = ?",
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
    // 1. Check existing user
    const check = await db.query(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (check.rows.length > 0) {
      return res.render("already-registered");
    }

    // 2. Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3. Insert user
    await db.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword]
    );

    // 4. Re-fetch user SAFELY (by email, not insertId)
    const userResult = await db.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (!userResult.rows.length) {
      throw new Error("User inserted but not found");
    }

    const user = userResult.rows[0];

    // 5. Login
    req.login(user, (err) => {
      if (err) {
        console.error("req.login error:", err);
        return res.redirect("/login");
      }
      return res.redirect("/dashboard");
    });

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).send(err.message);
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
      return res.status(500).render("login", {
        error: "Something went wrong. Please try again.",
      });
    }

    if (!user) {
      return res.render("login", {
        error: info?.message || "Invalid email or password",
      });
    }

    req.logIn(user, (err) => {
      if (err) {
        console.error("req.logIn error:", err);
        return res.status(500).render("login", {
          error: "Login failed. Please try again.",
        });
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
    await transporter.sendMail({
      from: `"SmrAI-Studio" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your SmrAI-Studio Password Reset OTP",
      text: `Your OTP for resetting your SmrAI-Studio password is: ${otp}. It is valid for 15 minutes.`,
    });
    return res.redirect(`/reset-password?email=${encodeURIComponent(email)}`);
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
    // console.log("SAVE RESUME BODY:", body);
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
         SET title = ?,
             template = ?,
             data = ?,
             updated_at = NOW()
         WHERE id = ? AND user_id = ?`,
        [
          title || "Untitled Resume",
          template || "modern-1",
          JSON.stringify(data),
          resumeId,
          userId,
        ]
      );

      if (result.affectedRows === 0) {
        return res
          .status(404)
          .json({ success: false, error: "Resume not found." });
      }

      savedId = Number(resumeId);
    } else {
      const insertResult = await db.query(
        `INSERT INTO resumes (user_id, title, template, data, created_at, updated_at)
         VALUES (?, ?, ?, ?, NOW(), NOW())`,
        [
          userId,
          title || "Untitled Resume",
          template || "modern-1",
          JSON.stringify(data),
        ]
      );

      savedId = insertResult.insertId;
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
    currentUser: req.user, // used by header
    user: req.user, // used in this EJS for email fallback
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
       WHERE r.user_id = ?
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
  const RESUME_TEMPLATES_VIEW = [
    {
      id: "modern-1",
      title: "Modern Professional",
      description:
        "Clean two-column layout, great for experienced professionals.",
      previewClass: "template-1",
      available: true,
      paid: true,
    },
    {
      id: "minimal-1",
      title: "Simple & Minimal",
      description:
        "Single-column layout, perfect for freshers and minimalist profiles.",
      previewClass: "template-3",
      available: false,
    },
  ];

  res.render("resume-templates", { RESUME_TEMPLATES: RESUME_TEMPLATES_VIEW });
});

// Show preview after form submit
app.post("/resume-builder/preview", ensureAuthenticated, async (req, res) => {
  const data = req.body;
  const template = data.template || req.session?.lastTemplate || "modern-1";

  try {
    // upsert profile using MySQL ON DUPLICATE KEY
    await db.query(
      `INSERT INTO user_profiles
        (user_id, full_name, role_title, location, phone, email, summary,
         experience, education, languages, skills, profile_image_url, updated_at)
       VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE
        full_name = VALUES(full_name),
        role_title = VALUES(role_title),
        location  = VALUES(location),
        phone     = VALUES(phone),
        email     = VALUES(email),
        summary   = VALUES(summary),
        experience = VALUES(experience),
        education  = VALUES(education),
        languages  = VALUES(languages),
        skills     = VALUES(skills),
        profile_image_url = VALUES(profile_image_url),
        updated_at = NOW()`,
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

// Generate PDF for download
// app.post("/resume-builder/pdf", ensureAuthenticated, (req, res) => {
//   const { fullName, email, phone, summary, experience, education, skills } =
//     req.body;

//   const doc = new PDFDocument({ margin: 50 });

//   res.setHeader("Content-Type", "application/pdf");
//   res.setHeader(
//     "Content-Disposition",
//     'attachment; filename="SmrAI-Studio-Resume.pdf"'
//   );

//   doc.pipe(res);

//   doc.fontSize(22).text(fullName || "", { align: "center" });
//   doc.moveDown(0.5);

//   const contactLine = `${email || ""} | ${phone || ""}`;
//   doc.fontSize(10).text(contactLine, { align: "center" });

//   doc.moveDown(1);
//   doc.fontSize(14).text("Summary");
//   doc.moveDown(0.2);
//   doc.fontSize(11).text(summary || "");

//   doc.moveDown(0.8);
//   doc.fontSize(14).text("Experience");
//   doc.moveDown(0.2);
//   doc.fontSize(11).text(experience || "");

//   doc.moveDown(0.8);
//   doc.fontSize(14).text("Education");
//   doc.moveDown(0.2);
//   doc.fontSize(11).text(education || "");

//   doc.moveDown(0.8);
//   doc.fontSize(14).text("Skills");
//   doc.moveDown(0.2);
//   doc.fontSize(11).text(skills || "");

//   doc.end();
// });

// Google Auth routes (will only work if strategy is enabled)
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
app.get("/dashboard", ensureAuthenticated, (req, res) => {
  res.render("dashboard");
});

// Logout
app.post("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) return next(err);

    req.session.destroy(() => {
      res.clearCookie("smrai.sid"); // name of the session cookie
      res.redirect("/login");
    });
  });
});

// Log free resume events (download / print for non-paid templates)
app.post("/resume/event", ensureAuthenticated, async (req, res) => {
  const userId = req.user.id;
  const { kind, resumeId } = req.body || {};

  if (!kind) {
    return res
      .status(400)
      .json({ success: false, message: "kind is required" });
  }

  try {
    await db.query(
      `INSERT INTO resume_events (user_id, resume_id, kind, meta)
       VALUES (?, ?, ?, ?)`,
      [userId, resumeId || null, kind, null]
    );

    return res.json({ success: true });
  } catch (err) {
    console.error("Error logging resume event:", err);
    return res.status(500).json({ success: false });
  }
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
      "INSERT INTO service_requests (name, email, service_type, details) VALUES (?, ?, ?, ?)",
      [name, email, service_type, details]
    );

    res.render("request-success");
  } catch (err) {
    console.error("Error saving request:", err);
    res.send(
      "Something went wrong while saving your request. Please try again."
    );
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

    // Upsert into user_profiles (MySQL)
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
    console.error("Error updating profile:", err);
    res.redirect("/dashboard");
  }
});

app.post(
  "/profile/photo",
  ensureAuthenticated,
  (req, res, next) => {
    upload.single("profilePhoto")(req, res, function (err) {
      if (err) {
        console.error("❌ Multer upload error:", err);
        return res.redirect("/dashboard");
      }
      next();
    });
  },
  async (req, res) => {
    if (!req.file) {
      return res.redirect("/dashboard");
    }

    const imagePath = "/uploads/" + req.file.filename;

    try {
      await db.query(
        `INSERT INTO user_profiles (user_id, profile_image_url, updated_at)
         VALUES (?, ?, NOW())
         ON DUPLICATE KEY UPDATE
           profile_image_url = VALUES(profile_image_url),
           updated_at = NOW()`,
        [req.user.id, imagePath]
      );
    } catch (err) {
      console.error("❌ DB error saving profile photo:", err);
    }

    const referer = req.get("referer") || "/dashboard";
    res.redirect(referer);
  }
);


// Create Razorpay order for ₹50 (modern-1 download/print)
app.post("/api/razorpay/create-order", ensureAuthenticated, async (req, res) => {
  if (!razorpay) {
    return res.status(503).json({
      success: false,
      message: "Payments are currently unavailable",
    });
  } 
  
  try {
    const options = {
      amount: 1 * 100, // ₹50 in paise
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
    res
      .status(500)
      .json({ success: false, message: "Unable to create order" });
  }
});

app.post("/api/razorpay/verify", async (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      purpose,
      resumeId,
    } = req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({
        success: false,
        message: "Missing Razorpay payment data",
      });
    }

    // Verify signature
    const hmac = crypto.createHmac(
      "sha256",
      process.env.RAZORPAY_KEY_SECRET
    );
    hmac.update(`${razorpay_order_id}|${razorpay_payment_id}`);
    const generatedSignature = hmac.digest("hex");

    if (generatedSignature !== razorpay_signature) {
      console.error("❌ Signature mismatch", {
        razorpay_order_id,
        razorpay_payment_id,
      });
      return res.status(400).json({
        success: false,
        message: "Invalid payment signature",
      });
    }

  // 🔒 Prevent duplicate verification
    const existing = await db.query(
      `SELECT id FROM payments WHERE razorpay_payment_id = ?`,
      [razorpay_payment_id]
    );

    if (existing.rows.length > 0) {
      return res.json({ success: true });
    }
    
    const userId = req.user ? req.user.id : null;

    await db.query(
      `INSERT INTO payments
       (user_id, resume_id, amount, currency, purpose,
        razorpay_order_id, razorpay_payment_id, razorpay_signature, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'captured')`,
      [
        userId,
        resumeId || null,
        1 * 100,
        "INR",
        purpose || "download",
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature,
      ]
    );

    await db.query(
      `INSERT INTO resume_events (user_id, resume_id, kind)
       VALUES (?, ?, ?)`,
      [userId, resumeId || null, purpose || "download"]
    );

    return res.json({ success: true });
  } catch (err) {
    console.error("❌ Razorpay verify error:", err);
    return res.status(500).json({
      success: false,
      message: "Payment verification failed",
    });
  }
});


// ---------- Health check ----------
app.get("/health", (req, res) => {
  res.send("OK");
});

// ---------- Start server ----------
app.listen(port, () => {
  console.log(`✅ Server running on port ${port}`);
});


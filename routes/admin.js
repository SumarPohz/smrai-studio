import { Router } from "express";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import { TEMPLATES } from "../config/templates-config.js";
import bcrypt from 'bcrypt';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Multer for static template image uploads
const tplImgDir = path.join(__dirname, "..", "public", "images", "templates", "uploads");
if (!fs.existsSync(tplImgDir)) fs.mkdirSync(tplImgDir, { recursive: true });

const tplImgStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, tplImgDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `tpl-${Date.now()}${ext}`);
  },
});
const tplUpload = multer({ storage: tplImgStorage, limits: { fileSize: 5 * 1024 * 1024 } });

// Multer for ad image uploads
const adImgDir = path.join(__dirname, "..", "public", "uploads", "ads");
if (!fs.existsSync(adImgDir)) fs.mkdirSync(adImgDir, { recursive: true });
const adImgStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, adImgDir),
  filename: (_req, file, cb) => { cb(null, `ad-${Date.now()}${path.extname(file.originalname)}`); },
});
const adUpload = multer({ storage: adImgStorage, limits: { fileSize: 5 * 1024 * 1024 } });

// Multer for preset music uploads (admin)
const musicDir = path.join(__dirname, '..', 'public', 'music');
if (!fs.existsSync(musicDir)) fs.mkdirSync(musicDir, { recursive: true });
const musicStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, musicDir),
  filename: (req, file, cb) => {
    const id   = ((req.body && req.body.musicId) || '').replace(/[^a-z0-9_-]/gi, '').toLowerCase() || 'track';
    const type = req.body && req.body.isPreview === '1' ? `preview-${id}` : id;
    cb(null, `${type}.mp3`);
  },
});
const musicUpload = multer({
  storage: musicStorage,
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (_req, f, cb) => cb(null, /mp3|wav|mpeg|audio/.test(f.mimetype)),
});

// Multer for art style GIF uploads (admin)
const artGifDir = path.join(__dirname, '..', 'public', 'uploads', 'art-gifs');
if (!fs.existsSync(artGifDir)) fs.mkdirSync(artGifDir, { recursive: true });
const artGifStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, artGifDir),
  filename: (req, _file, cb) => {
    const id = ((req.body && req.body.artId) || '').replace(/[^a-z0-9_-]/gi, '').toLowerCase() || 'style';
    cb(null, `${id}.gif`);
  },
});
const artGifUpload = multer({ storage: artGifStorage, limits: { fileSize: 10 * 1024 * 1024 } });

const ADMIN_SECTIONS = ["overview","users","activity","requests","pricing","templates","homepage","ads","coupons","apikeys","investors","wallet","subscriptions","paysetu","plans"];

// Map API path prefixes → section key (for write-guard)
const SECTION_API_MAP = [
  { prefix: "/api/user",             section: "users"     },
  { prefix: "/api/pricing",          section: "pricing"   },
  { prefix: "/api/templates",        section: "templates" },
  { prefix: "/api/template",         section: "templates" },
  { prefix: "/api/homepage",         section: "homepage"  },
  { prefix: "/api/ads",              section: "ads"       },
  { prefix: "/api/coupon",           section: "coupons"   },
  { prefix: "/api/investor",         section: "investors" },
  { prefix: "/api/investment",       section: "investors" },
  { prefix: "/api/env-settings",     section: "apikeys"   },
  { prefix: "/api/wallet",           section: "wallet"    },
  { prefix: "/api/paysetu",          section: "paysetu"   },
];

export default function adminRouter(db) {
  const router = Router();

  // ── Sub-admin permissions middleware ───────────────────────────────────────
  router.use(async (req, res, next) => {
    if (req.user?.role === "subadmin") {
      try {
        const rows = await db.query("SELECT section, level FROM subadmin_permissions WHERE user_id=?", [req.user.id]);
        req.subadminPerms = Object.fromEntries(rows.rows.map(r => [r.section, r.level]));
      } catch (_) { req.subadminPerms = {}; }
      // Block write requests for sections without edit permission
      if (req.method !== "GET") {
        const path = req.path;
        const match = SECTION_API_MAP.find(m => path.startsWith(m.prefix));
        if (match && req.subadminPerms[match.section] !== "edit") {
          return res.status(403).json({ success: false, message: "No edit permission for this section" });
        }
      }
    } else {
      req.subadminPerms = null; // full admin — unrestricted
    }
    next();
  });

  // ── GET /admin — server-rendered dashboard with stats ──────────────────────
  router.get("/", async (req, res) => {
    try {
      const [users, resumes, downloads, revenue, aiUse, active24h, myInv, myProfile, companyRow, psVolume] = await Promise.all([
        db.query("SELECT COUNT(*) AS count FROM users"),
        db.query("SELECT COUNT(*) AS count FROM resumes"),
        db.query("SELECT COUNT(*) AS count FROM resume_events WHERE kind = 'download'"),
        db.query("SELECT COALESCE(SUM(amount),0) AS total FROM payments WHERE status = 'captured'"),
        db.query("SELECT COUNT(*) AS count FROM activity_logs WHERE action_type LIKE 'ai_%'"),
        db.query("SELECT COUNT(DISTINCT user_id) AS count FROM activity_logs WHERE created_at > NOW() - INTERVAL 24 HOUR"),
        db.query("SELECT * FROM investments WHERE user_id=? ORDER BY created_at DESC LIMIT 1", [req.user.id]),
        db.query("SELECT full_name, profile_image_url FROM user_profiles WHERE user_id=?", [req.user.id]),
        db.query("SELECT value FROM admin_settings WHERE `key`='company_name'"),
        db.query("SELECT COALESCE(SUM(amount),0) AS total FROM (SELECT amount FROM recharge_transactions WHERE status='success' UNION ALL SELECT amount FROM bbps_transactions WHERE status='success') AS ps"),
      ]);

      const isSubAdmin = req.user.role === "subadmin";
      // req.subadminPerms already populated by middleware
      const myPerms = isSubAdmin ? (req.subadminPerms || {}) : null;

      res.render("admin/dashboard", {
        stats: {
          totalUsers:     +users.rows[0].count,
          activeToday:    +active24h.rows[0].count,
          totalResumes:   +resumes.rows[0].count,
          totalDownloads: +downloads.rows[0].count,
          totalRevenue:   Math.round(+revenue.rows[0].total / 100), // paise → rupees
          aiRequests:     +aiUse.rows[0].count,
          paysetuVolume:  Math.round(+psVolume.rows[0].total),
        },
        myInvestment: myInv.rows[0] || null,
        myProfile:    myProfile.rows[0] || null,
        companyName:  companyRow.rows[0]?.value || 'SmrAI Studio',
        isSubAdmin,
        myPerms,
      });
    } catch (err) {
      console.error("[admin dashboard error]", err.message);
      res.status(500).send("Dashboard error: " + err.message);
    }
  });

  // ── GET /admin/api/users — paginated user list ─────────────────────────────
  router.get("/api/users", async (req, res) => {
    try {
      const page   = Math.max(1, parseInt(req.query.page)  || 1);
      const limit  = Math.min(50, parseInt(req.query.limit) || 20);
      const offset = (page - 1) * limit;
      const q      = req.query.q ? `%${req.query.q}%` : null;

      const sql = `
        SELECT
          u.id, u.name, u.email, u.role, u.is_active, u.created_at, u.wallet_balance,
          up.full_name, up.phone, up.location, up.profile_image_url,
          (SELECT COUNT(*) FROM resumes        WHERE user_id = u.id)                           AS resume_count,
          (SELECT COUNT(*) FROM resume_events  WHERE user_id = u.id AND kind = 'download')     AS download_count,
          (SELECT COALESCE(SUM(p.amount),0) FROM payments p WHERE p.user_id = u.id AND p.status = 'captured') AS total_paid,
          (SELECT MAX(al.created_at) FROM activity_logs al WHERE al.user_id = u.id)                AS last_active,
          EXISTS(SELECT 1 FROM investments WHERE user_id = u.id)                                    AS has_investment
        FROM users u
        LEFT JOIN user_profiles up ON up.user_id = u.id
        ${q ? "WHERE u.name LIKE ? OR u.email LIKE ?" : ""}
        ORDER BY u.id DESC
        LIMIT ? OFFSET ?
      `;

      const countSql = `SELECT COUNT(*) AS count FROM users u ${q ? "WHERE u.name LIKE ? OR u.email LIKE ?" : ""}`;

      const [rows, countRes] = await Promise.all([
        db.query(sql,      q ? [q, q, limit, offset] : [limit, offset]),
        db.query(countSql, q ? [q, q] : []),
      ]);

      res.json({
        success: true,
        users:   rows.rows,
        total:   +countRes.rows[0].count,
        page,
        limit,
      });
    } catch (err) {
      console.error("[admin/api/users error]", err.message);
      res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /admin/api/user/:id — full user detail for modal (admin only) ───────
  router.get("/api/user/:id", async (req, res) => {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, message: "Admin only" });
    try {
      const id = parseInt(req.params.id);
      if (!id) return res.status(400).json({ success: false });

      const [userRes, profileRes, countsRes] = await Promise.all([
        db.query(
          "SELECT id, name, email, role, is_active, created_at, wallet_balance, EXISTS(SELECT 1 FROM investments WHERE user_id=?) AS has_investment FROM users WHERE id = ?",
          [id, id]
        ),
        db.query("SELECT * FROM user_profiles WHERE user_id = ?", [id]),
        db.query(
          `SELECT
            (SELECT COUNT(*) FROM resumes        WHERE user_id = ?)                           AS resumes,
            (SELECT COUNT(*) FROM resume_events  WHERE user_id = ? AND kind = 'download')     AS downloads,
            (SELECT COUNT(*) FROM activity_logs  WHERE user_id = ? AND action_type LIKE 'ai_%') AS ai_uses,
            (SELECT COALESCE(SUM(amount),0) FROM payments WHERE user_id = ? AND status = 'captured') AS total_paid,
            (SELECT MAX(created_at) FROM activity_logs WHERE user_id = ?)                          AS last_active`,
          [id, id, id, id, id]
        ),
      ]);

      if (!userRes.rows.length) return res.status(404).json({ success: false });

      const profile = profileRes.rows[0] || {};
      const counts  = countsRes.rows[0]  || {};

      res.json({
        success: true,
        user: {
          id:                userRes.rows[0].id,
          name:              userRes.rows[0].name,
          email:             userRes.rows[0].email,
          role:              userRes.rows[0].role,
          is_active:         userRes.rows[0].is_active,
          full_name:         profile.full_name         || null,
          phone:             profile.phone             || null,
          location:          profile.location          || null,
          profile_image_url: profile.profile_image_url || null,
          resumes:           counts.resumes     || 0,
          downloads:         counts.downloads   || 0,
          ai_uses:           counts.ai_uses     || 0,
          total_paid:        Math.round(+counts.total_paid / 100),
          last_active:       counts.last_active || null,
          created_at:        userRes.rows[0].created_at || null,
          wallet_balance:    parseFloat(userRes.rows[0].wallet_balance) || 0,
        },
      });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── POST /admin/api/user/:id/role — toggle user role ─────────────────────
  router.post("/api/user/:id/role", async (req, res) => {
    try {
      const id   = parseInt(req.params.id);
      const role = req.body.role;

      if (!id || !["admin", "subadmin", "user"].includes(role)) {
        return res.status(400).json({ success: false, message: "Invalid request" });
      }
      if (id === req.user.id && role === "user") {
        return res.status(403).json({ success: false, message: "Cannot demote yourself" });
      }
      // Only main admin can set admin/subadmin roles
      if (req.user.role !== "admin") {
        return res.status(403).json({ success: false, message: "Only main admin can change roles" });
      }

      await db.query("UPDATE users SET role = ? WHERE id = ?", [role, id]);

      // Seed default permissions when promoting to subadmin
      if (role === "subadmin") {
        const SECTIONS = ["overview","users","activity","requests","pricing","templates","homepage","ads","coupons","apikeys","investors"];
        for (const section of SECTIONS) {
          await db.query(
            `INSERT IGNORE INTO subadmin_permissions (user_id, section, level) VALUES (?, ?, 'none')`,
            [id, section]
          );
        }
      }
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/api/user/:id/permissions — get subadmin permissions ─────────
  router.get("/api/user/:id/permissions", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const rows = await db.query("SELECT section, level FROM subadmin_permissions WHERE user_id=?", [id]);
      const perms = Object.fromEntries(ADMIN_SECTIONS.map(s => [s, "none"]));
      for (const r of rows.rows) perms[r.section] = r.level;
      res.json({ success: true, permissions: perms });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  // ── PATCH /admin/api/user/:id/permissions — update subadmin permissions ────
  router.patch("/api/user/:id/permissions", async (req, res) => {
    try {
      if (req.user.role !== "admin") return res.status(403).json({ success: false, message: "Only main admin can edit permissions" });
      const id = parseInt(req.params.id);
      const sections = req.body.sections || {};
      for (const [section, level] of Object.entries(sections)) {
        if (!ADMIN_SECTIONS.includes(section)) continue;
        if (!["none","view","edit"].includes(level)) continue;
        await db.query(
          `INSERT INTO subadmin_permissions (user_id, section, level) VALUES (?,?,?)
           ON DUPLICATE KEY UPDATE level=VALUES(level)`,
          [id, section, level]
        );
      }
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  // ── PATCH /admin/api/user/:id/toggle-active — activate / deactivate ──────
  router.patch("/api/user/:id/toggle-active", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (!id) return res.status(400).json({ success: false });
      if (id === req.user.id) {
        return res.status(403).json({ success: false, message: "Cannot deactivate yourself" });
      }
      const curRow = await db.query("SELECT is_active FROM users WHERE id = ?", [id]);
      if (!curRow.rows.length) return res.status(404).json({ success: false });
      const newActive = !curRow.rows[0].is_active;
      await db.query("UPDATE users SET is_active = ? WHERE id = ?", [newActive, id]);
      res.json({ success: true, is_active: newActive });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── DELETE /admin/api/user/:id — permanently delete a user ───────────────
  router.delete("/api/user/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (!id) return res.status(400).json({ success: false });
      if (id === req.user.id) {
        return res.status(403).json({ success: false, message: "Cannot delete yourself" });
      }
      await db.query("DELETE FROM users WHERE id = ?", [id]);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── POST /admin/api/user/:id/set-password — admin changes user password ──
  router.post("/api/user/:id/set-password", async (req, res) => {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, message: "Admin only" });
    const id = parseInt(req.params.id);
    const { password } = req.body || {};
    if (!id) return res.json({ success: false, message: "Invalid user." });
    if (!password || password.length < 6) return res.json({ success: false, message: "Password must be at least 6 characters." });
    try {
      const hash = await bcrypt.hash(password, 10);
      await db.query("UPDATE users SET password = ? WHERE id = ?", [hash, id]);
      res.json({ success: true, message: "Password updated successfully." });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // ── POST /admin/api/user/:id/set-pin — admin sets wallet PIN for user ─────
  router.post("/api/user/:id/set-pin", async (req, res) => {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, message: "Admin only" });
    const id = parseInt(req.params.id);
    const pin = String(req.body.pin || "").trim();
    if (!id) return res.json({ success: false, message: "Invalid user." });
    if (!/^\d{4}$/.test(pin)) return res.json({ success: false, message: "PIN must be exactly 4 digits." });
    try {
      const hash = await bcrypt.hash(pin, 10);
      await db.query("UPDATE users SET wallet_pin = ? WHERE id = ?", [hash, id]);
      res.json({ success: true, message: "Wallet PIN set successfully." });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // ── DELETE /admin/api/activity — clear logs by period ────────────────────
  router.delete("/api/activity", async (req, res) => {
    const { period } = req.query;
    try {
      let result;
      if (period === "recent") {
        result = await db.query(
          `DELETE FROM activity_logs WHERE created_at >= NOW() - INTERVAL 1 HOUR`
        );
      } else if (period === "today") {
        result = await db.query(
          `DELETE FROM activity_logs WHERE DATE(created_at) = CURDATE()`
        );
      } else if (period === "yesterday") {
        result = await db.query(
          `DELETE FROM activity_logs WHERE DATE(created_at) = DATE(NOW() - INTERVAL 1 DAY)`
        );
      } else if (period === "all") {
        result = await db.query(`DELETE FROM activity_logs`);
      } else {
        return res.status(400).json({ success: false, error: "Invalid period" });
      }
      res.json({ success: true, deleted: result.rowCount });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/api/activity — latest activity feed ────────────────────────
  router.get("/api/activity", async (req, res) => {
    try {
      const limit = Math.min(100, parseInt(req.query.limit) || 50);
      const rows = await db.query(
        `SELECT
          al.id, al.user_id, al.action_type, al.route, al.metadata, al.ip_address, al.created_at,
          u.name AS user_name, u.email AS user_email,
          up.profile_image_url
        FROM activity_logs al
        LEFT JOIN users u         ON u.id = al.user_id
        LEFT JOIN user_profiles up ON up.user_id = al.user_id
        ORDER BY al.created_at DESC
        LIMIT ?`,
        [limit]
      );
      res.json({ success: true, activities: rows.rows });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/api/activity-grouped — one row per user + guest summary ────
  router.get("/api/activity-grouped", async (req, res) => {
    try {
      const [userRows, guestRow] = await Promise.all([
        db.query(
          `SELECT
             al.user_id,
             u.name  AS user_name,
             u.email AS user_email,
             up.profile_image_url,
             COUNT(*)                              AS activity_count,
             MAX(al.created_at)                    AS last_active,
             (SELECT action_type FROM activity_logs
              WHERE user_id = al.user_id
              ORDER BY created_at DESC LIMIT 1)    AS last_action,
             (SELECT route FROM activity_logs
              WHERE user_id = al.user_id
              ORDER BY created_at DESC LIMIT 1)    AS last_route
           FROM activity_logs al
           LEFT JOIN users u          ON u.id = al.user_id
           LEFT JOIN user_profiles up ON up.user_id = al.user_id
           WHERE al.user_id IS NOT NULL
           GROUP BY al.user_id, u.name, u.email, up.profile_image_url
           ORDER BY last_active DESC
           LIMIT 30`
        ),
        // Count anonymous visitor sessions
        db.query(
          `SELECT
             COUNT(*)                                   AS total_visits,
             COUNT(DISTINCT JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.sid'))) AS unique_sessions,
             MAX(created_at)                            AS last_visit,
             (SELECT route FROM activity_logs
              WHERE user_id IS NULL AND action_type = 'visit'
              ORDER BY created_at DESC LIMIT 1)         AS last_route
           FROM activity_logs
           WHERE user_id IS NULL AND action_type = 'visit'`
        ),
      ]);

      const users = userRows.rows;

      // Prepend a synthetic guest row if any anonymous visits exist
      const g = guestRow.rows[0];
      if (g && g.total_visits > 0) {
        users.unshift({
          user_id:          null,
          is_guest:         true,
          user_name:        "Anonymous Visitors",
          user_email:       null,
          profile_image_url: null,
          activity_count:   g.total_visits,
          unique_sessions:  g.unique_sessions,
          last_active:      g.last_visit,
          last_action:      "visit",
          last_route:       g.last_route,
        });
      }

      res.json({ success: true, users });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/api/guest-activity — route breakdown for anonymous visitors ─
  router.get("/api/guest-activity", async (req, res) => {
    try {
      const [routeRows, recentRows] = await Promise.all([
        db.query(
          `SELECT route, COUNT(*) AS visits, MAX(created_at) AS last_visit
           FROM activity_logs
           WHERE user_id IS NULL AND action_type = 'visit' AND route IS NOT NULL
           GROUP BY route
           ORDER BY visits DESC
           LIMIT 20`
        ),
        db.query(
          `SELECT route, ip_address, created_at
           FROM activity_logs
           WHERE user_id IS NULL AND action_type = 'visit'
           ORDER BY created_at DESC
           LIMIT 15`
        ),
      ]);
      res.json({ success: true, routes: routeRows.rows, recent: recentRows.rows });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/api/user-activity/:id — full activity list for one user ────
  router.get("/api/user-activity/:id", async (req, res) => {
    try {
      const rows = await db.query(
        `SELECT action_type, route, created_at, metadata
         FROM activity_logs
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT 60`,
        [req.params.id]
      );
      res.json({ success: true, activities: rows.rows });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/api/stat-detail — drill-down data for stat cards ──────────
  router.get("/api/stat-detail", async (req, res) => {
    const { type } = req.query;
    try {
      let result;
      if (type === "resumes") {
        result = await db.query(
          `SELECT r.id, r.name, r.template, r.updated_at,
             u.name AS user_name, u.email
           FROM resumes r
           LEFT JOIN users u ON u.id = r.user_id
           ORDER BY r.updated_at DESC LIMIT 30`
        );
      } else if (type === "downloads") {
        result = await db.query(
          `SELECT re.created_at, r.name AS resume_name, r.template,
             u.name AS user_name, u.email
           FROM resume_events re
           LEFT JOIN resumes r ON r.id = re.resume_id
           LEFT JOIN users u   ON u.id = re.user_id
           WHERE re.kind = 'download'
           ORDER BY re.created_at DESC LIMIT 30`
        );
      } else if (type === "revenue") {
        result = await db.query(
          `SELECT p.amount, p.created_at,
             u.name AS user_name, u.email,
             r.name AS resume_name
           FROM payments p
           LEFT JOIN users u   ON u.id = p.user_id
           LEFT JOIN resumes r ON r.id = p.resume_id
           WHERE p.status = 'captured'
           ORDER BY p.created_at DESC LIMIT 30`
        );
      } else if (type === "ai") {
        result = await db.query(
          `SELECT al.action_type, al.route, al.created_at,
             u.name AS user_name, u.email
           FROM activity_logs al
           LEFT JOIN users u ON u.id = al.user_id
           WHERE al.action_type LIKE 'ai_%'
           ORDER BY al.created_at DESC LIMIT 30`
        );
      } else {
        return res.status(400).json({ success: false });
      }
      res.json({ success: true, rows: result.rows });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/api/charts — data for Chart.js visualisations ─────────────
  router.get("/api/charts", async (req, res) => {
    try {
      const [routeHits, templateDownloads, dailyRevenue, dailyAI] = await Promise.all([
        db.query(
          `SELECT route, COUNT(*) AS hits
           FROM activity_logs WHERE action_type = 'visit' AND route IS NOT NULL
           GROUP BY route ORDER BY hits DESC LIMIT 8`
        ),
        db.query(
          `SELECT r.template, COUNT(*) AS downloads
           FROM resume_events re
           JOIN resumes r ON r.id = re.resume_id
           WHERE re.kind = 'download'
           GROUP BY r.template ORDER BY downloads DESC`
        ),
        db.query(
          `SELECT DATE(created_at) AS day, ROUND(SUM(amount)/100.0, 2) AS revenue
           FROM payments WHERE status = 'captured' AND created_at > NOW() - INTERVAL 30 DAY
           GROUP BY day ORDER BY day`
        ),
        db.query(
          `SELECT DATE(created_at) AS day, COUNT(*) AS count
           FROM activity_logs WHERE action_type LIKE 'ai_%' AND created_at > NOW() - INTERVAL 30 DAY
           GROUP BY day ORDER BY day`
        ),
      ]);

      res.json({
        success: true,
        routeHits:         routeHits.rows,
        templateDownloads: templateDownloads.rows,
        dailyRevenue:      dailyRevenue.rows,
        dailyAI:           dailyAI.rows,
      });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/api/service-requests — paginated list ─────────────────────
  router.get("/api/service-requests", async (req, res) => {
    try {
      const page   = Math.max(1, parseInt(req.query.page)  || 1);
      const limit  = Math.min(50, parseInt(req.query.limit) || 20);
      const offset = (page - 1) * limit;
      const status = req.query.status || null;

      const where  = status ? "WHERE status = ?" : "";
      const params = status ? [status, limit, offset] : [limit, offset];

      const [rows, countRes] = await Promise.all([
        db.query(
          `SELECT id, name, email, service_type, details, status, created_at
           FROM service_requests
           ${where}
           ORDER BY created_at DESC
           LIMIT ? OFFSET ?`,
          params
        ),
        db.query(
          `SELECT COUNT(*) AS count FROM service_requests ${status ? "WHERE status = ?" : ""}`,
          status ? [status] : []
        ),
      ]);

      res.json({ success: true, requests: rows.rows, total: countRes.rows[0].count, page, limit });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── PATCH /admin/api/service-request/:id/status — update status ───────────
  router.patch("/api/service-request/:id/status", async (req, res) => {
    try {
      const id     = parseInt(req.params.id);
      const status = req.body.status;
      if (!id || !["new", "in_progress", "done", "closed"].includes(status)) {
        return res.status(400).json({ success: false });
      }
      await db.query("UPDATE service_requests SET status = ? WHERE id = ?", [status, id]);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── DELETE /admin/api/service-request/:id — delete a request ─────────────
  router.delete("/api/service-request/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (!id) return res.status(400).json({ success: false });
      await db.query("DELETE FROM service_requests WHERE id = ?", [id]);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/api/settings — return all key-value settings ──────────────
  router.get("/api/settings", async (req, res) => {
    try {
      const result = await db.query("SELECT `key`, value FROM admin_settings ORDER BY `key`");
      const settings = {};
      for (const row of result.rows) settings[row.key] = row.value;
      res.json({ success: true, settings });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── PATCH /admin/api/settings — update one or more settings ──────────────
  router.patch("/api/settings", async (req, res) => {
    try {
      const PRICE_KEYS   = ["price_fresher", "price_experienced", "price_developer", "price_ats-friendly", "dth_recharge_min", "dth_recharge_max", "wallet_cap", "price_reel_video"];
      const GENERAL_KEYS = ["adsense_publisher_id", "facebook_pixel_id", "homepage_ad_slot", "footer_ad_slot", "ads_enabled", "google_translate_enabled", "reel_image_provider"];
      const ALLOWED_KEYS = [...PRICE_KEYS, ...GENERAL_KEYS];
      const updates = req.body || {};
      const entries = Object.entries(updates).filter(([k]) => ALLOWED_KEYS.includes(k));

      if (!entries.length) return res.status(400).json({ success: false, message: "No valid keys" });

      for (const [key, value] of entries) {
        if (PRICE_KEYS.includes(key)) {
          const num = parseInt(value, 10);
          if (isNaN(num) || num < 0) return res.status(400).json({ success: false, message: `Invalid value for ${key}` });
          await db.query(
            `INSERT INTO admin_settings (\`key\`, value, updated_at) VALUES (?, ?, NOW())
             ON DUPLICATE KEY UPDATE value = VALUES(value), updated_at = NOW()`,
            [key, String(num)]
          );
        } else {
          const strVal = String(value ?? '').trim();
          await db.query(
            `INSERT INTO admin_settings (\`key\`, value, updated_at) VALUES (?, ?, NOW())
             ON DUPLICATE KEY UPDATE value = VALUES(value), updated_at = NOW()`,
            [key, strVal]
          );
        }
      }

      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/api/templates — list all admin-created templates ──────────
  router.get("/api/templates", async (req, res) => {
    try {
      const rows = await db.query(`
        SELECT t.*,
          (SELECT COUNT(*) FROM admin_template_sections s WHERE s.template_id = t.id AND s.is_enabled = true) AS enabled_sections,
          (SELECT COUNT(*) FROM resumes r WHERE r.template = t.slug) AS usage_count
        FROM admin_templates t
        ORDER BY t.sort_order, t.created_at DESC
      `);
      res.json({ success: true, templates: rows.rows });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── POST /admin/api/templates — create a new template ────────────────────
  router.post("/api/templates", async (req, res) => {
    try {
      const { title, description, category, badge, layout_type, color_scheme, is_paid, price_inr } = req.body || {};
      if (!title) return res.status(400).json({ success: false, error: "Title required" });

      // Create with temporary slug first
      const tempSlug = `adm-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-").substring(0, 40)}-tmp`;
      const insert = await db.query(
        `INSERT INTO admin_templates (slug, title, description, category, badge, layout_type, color_scheme, is_paid, price_inr, created_by)
         VALUES (?,?,?,?,?,?,?,?,?,?)`,
        [
          tempSlug, title, description || null,
          category || "experienced", badge || "New",
          layout_type || "two-column-left",
          JSON.stringify(color_scheme || { primary: "#1e3a5f", secondary: "#f3f4f6", accent: "#3b82f6", text: "#1f2937" }),
          is_paid !== false, price_inr || 49, req.user.id,
        ]
      );
      const newId = insert.insertId;
      // Update slug to include real id
      const finalSlug = `adm-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-").substring(0, 40)}-${newId}`;
      await db.query("UPDATE admin_templates SET slug=?, updated_at=NOW() WHERE id=?", [finalSlug, newId]);

      // Insert default sections
      const defaultSections = [
        { key: "summary",        order: 1,  placement: "main",    display: "plain",    disabled: false },
        { key: "experience",     order: 2,  placement: "main",    display: "timeline", disabled: false },
        { key: "education",      order: 3,  placement: "sidebar", display: "bullets",  disabled: false },
        { key: "skills",         order: 4,  placement: "sidebar", display: "pills",    disabled: false },
        { key: "languages",      order: 5,  placement: "sidebar", display: "pills",    disabled: false },
        { key: "certifications", order: 6,  placement: "sidebar", display: "bullets",  disabled: false },
        { key: "technologies",   order: 7,  placement: "main",    display: "bullets",  disabled: false },
        { key: "projects",       order: 8,  placement: "main",    display: "bullets",  disabled: false },
        { key: "achievements",   order: 9,  placement: "main",    display: "bullets",  disabled: false },
        { key: "volunteering",   order: 10, placement: "main",    display: "bullets",  disabled: false },
        { key: "references",     order: 11, placement: "sidebar", display: "bullets",  disabled: false },
        { key: "hobbies",        order: 12, placement: "sidebar", display: "pills",    disabled: true  },
        { key: "awards",         order: 13, placement: "main",    display: "bullets",  disabled: true  },
        { key: "training",       order: 14, placement: "main",    display: "bullets",  disabled: true  },
        { key: "publications",   order: 15, placement: "main",    display: "bullets",  disabled: true  },
        { key: "custom_1",       order: 16, placement: "main",    display: "bullets",  disabled: true  },
        { key: "custom_2",       order: 17, placement: "main",    display: "bullets",  disabled: true  },
        { key: "custom_3",       order: 18, placement: "main",    display: "bullets",  disabled: true  },
      ];
      for (const s of defaultSections) {
        await db.query(
          `INSERT INTO admin_template_sections
             (template_id, section_key, is_enabled, sort_order, placement, display_type, label_override)
           VALUES (?,?,?,?,?,?,?)`,
          [newId, s.key, !s.disabled, s.order, s.placement, s.display, null]
        );
      }

      const tpl = await db.query("SELECT * FROM admin_templates WHERE id=?", [newId]);
      res.json({ success: true, template: tpl.rows[0] });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ── PUT /admin/api/templates/:id — update template ───────────────────────
  router.put("/api/templates/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (!id) return res.status(400).json({ success: false });
      const { title, description, category, badge, layout_type, color_scheme, is_paid, price_inr, sort_order, design_settings } = req.body || {};
      const DEFAULT_DESIGN = { fontFamily:"segoe", headingWeight:"800", bodySize:"medium", borderRadius:"soft", shadow:"none", sectionTitleStyle:"underline", headerStyle:"classic", pillShape:"rounded" };
      await db.query(
        `UPDATE admin_templates SET
          title=?, description=?, category=?, badge=?, layout_type=?,
          color_scheme=?, is_paid=?, price_inr=?, sort_order=?,
          design_settings=?, updated_at=NOW()
         WHERE id=?`,
        [
          title, description || null, category || "experienced", badge || "New",
          layout_type || "two-column-left",
          JSON.stringify(color_scheme || { primary: "#1e3a5f", secondary: "#f3f4f6", accent: "#3b82f6", text: "#1f2937" }),
          is_paid !== false, price_inr || 49, sort_order || 0,
          JSON.stringify(design_settings || DEFAULT_DESIGN),
          id,
        ]
      );
      const tpl = await db.query("SELECT * FROM admin_templates WHERE id=?", [id]);
      res.json({ success: true, template: tpl.rows[0] });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // ── DELETE /admin/api/templates/:id — delete template ────────────────────
  router.delete("/api/templates/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (!id) return res.status(400).json({ success: false });
      await db.query("DELETE FROM admin_templates WHERE id=?", [id]);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── POST /admin/api/templates/:id/publish — toggle publish ───────────────
  router.post("/api/templates/:id/publish", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (!id) return res.status(400).json({ success: false });
      const current = await db.query("SELECT is_published FROM admin_templates WHERE id=?", [id]);
      if (!current.rows[0]) return res.status(404).json({ success: false });
      const newState = !current.rows[0].is_published;
      await db.query("UPDATE admin_templates SET is_published=?, updated_at=NOW() WHERE id=?", [newState, id]);
      res.json({ success: true, is_published: newState });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── POST /admin/api/templates/:id/thumbnail — save thumbnail URL (or null to clear) ──
  router.post("/api/templates/:id/thumbnail", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (!id) return res.status(400).json({ success: false });
      const { thumbnailUrl } = req.body || {};
      await db.query(
        "UPDATE admin_templates SET thumbnail_url=?, updated_at=NOW() WHERE id=?",
        [thumbnailUrl || null, id]
      );
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── POST /admin/api/templates/:id/image — upload thumbnail image file ──────
  router.post("/api/templates/:id/image", tplUpload.single("image"), async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (!id || !req.file) return res.status(400).json({ success: false });
      const imageUrl = `/images/templates/uploads/${req.file.filename}`;
      await db.query(
        "UPDATE admin_templates SET thumbnail_url=?, updated_at=NOW() WHERE id=?",
        [imageUrl, id]
      );
      res.json({ success: true, imageUrl });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── POST /admin/api/templates/:id/background — upload background image ──────
  router.post("/api/templates/:id/background", tplUpload.single("image"), async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (!id || !req.file) return res.status(400).json({ success: false, error: "No file" });
      const imageUrl = `/images/templates/uploads/${req.file.filename}`;
      await db.query(
        "UPDATE admin_templates SET background_image_url=?, updated_at=NOW() WHERE id=?",
        [imageUrl, id]
      );
      res.json({ success: true, imageUrl });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── DELETE /admin/api/templates/:id/background — remove background image ────
  router.delete("/api/templates/:id/background", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (!id) return res.status(400).json({ success: false });
      await db.query("UPDATE admin_templates SET background_image_url=NULL, updated_at=NOW() WHERE id=?", [id]);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/api/templates/:id/sections — get section config ────────────
  router.get("/api/templates/:id/sections", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (!id) return res.status(400).json({ success: false });
      const rows = await db.query(
        "SELECT section_key, is_enabled, sort_order, placement, display_type, label_override FROM admin_template_sections WHERE template_id=? ORDER BY sort_order",
        [id]
      );
      res.json({ success: true, sections: rows.rows });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── POST /admin/api/templates/:id/sections — bulk-replace section config ──
  router.post("/api/templates/:id/sections", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (!id) return res.status(400).json({ success: false });
      const { sections } = req.body || {};
      if (!Array.isArray(sections)) return res.status(400).json({ success: false, error: "sections must be array" });

      // Delete existing and re-insert
      await db.query("DELETE FROM admin_template_sections WHERE template_id=?", [id]);
      for (const s of sections) {
        await db.query(
          `INSERT INTO admin_template_sections
             (template_id, section_key, is_enabled, sort_order, placement, display_type, label_override)
           VALUES (?,?,?,?,?,?,?)`,
          [id, s.section_key, s.is_enabled !== false, s.sort_order || 0,
           s.placement || 'auto', s.display_type || 'bullets', s.label_override || null]
        );
      }
      await db.query("UPDATE admin_templates SET updated_at=NOW() WHERE id=?", [id]);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ════════════════════════════════════════════════════════════════════════════
  //  HOMEPAGE CONTENT MANAGEMENT
  // ════════════════════════════════════════════════════════════════════════════

  // ── GET /admin/api/homepage — all 4 sections ────────────────────────────────
  router.get("/api/homepage", async (_req, res) => {
    try {
      const keys = ["homepage_hero","homepage_services","homepage_features","homepage_testimonials"];
      const rows = (await db.query(`SELECT \`key\`, value FROM admin_settings WHERE \`key\` IN (?,?,?,?)`, keys)).rows;
      const data = Object.fromEntries(rows.map(r => [r.key.replace("homepage_",""), JSON.parse(r.value)]));
      res.json({ success: true, data });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── PUT /admin/api/homepage/:section — upsert one section ───────────────────
  router.put("/api/homepage/:section", async (req, res) => {
    try {
      const allowed = ["hero","services","features","testimonials"];
      const { section } = req.params;
      if (!allowed.includes(section)) return res.status(400).json({ success: false, error: "Invalid section" });
      const key   = `homepage_${section}`;
      const value = JSON.stringify(req.body);
      await db.query(
        `INSERT INTO admin_settings (\`key\`, value, updated_at) VALUES (?,?,NOW())
         ON DUPLICATE KEY UPDATE value=VALUES(value), updated_at=NOW()`,
        [key, value]
      );
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── POST /admin/api/homepage/upload-image — upload avatar/service image ──────
  // Stores as base64 data URL so images survive Render's ephemeral filesystem restarts
  router.post("/api/homepage/upload-image", tplUpload.single("image"), (req, res) => {
    if (!req.file) return res.status(400).json({ success: false, error: "No file uploaded" });
    const b64 = req.file.buffer
      ? `data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`
      : `data:${req.file.mimetype};base64,${fs.readFileSync(req.file.path).toString("base64")}`;
    // Clean up temp file if saved to disk
    if (req.file.path) { try { fs.unlinkSync(req.file.path); } catch(_){} }
    res.json({ success: true, imageUrl: b64 });
  });

  // ── GET /admin/api/bgremover/backgrounds — fetch admin-uploaded bg images ─────
  router.get("/api/bgremover/backgrounds", async (_req, res) => {
    try {
      const r = await db.query("SELECT value FROM admin_settings WHERE `key`='bgremover_backgrounds'");
      const images = r.rows.length ? JSON.parse(r.rows[0].value) : [];
      res.json({ success: true, images });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── PUT /admin/api/bgremover/backgrounds — save admin-uploaded bg images ──────
  router.put("/api/bgremover/backgrounds", async (req, res) => {
    try {
      const images = Array.isArray(req.body.images) ? req.body.images : [];
      await db.query(
        `INSERT INTO admin_settings (\`key\`, value, updated_at) VALUES ('bgremover_backgrounds',?,NOW())
         ON DUPLICATE KEY UPDATE value=VALUES(value), updated_at=NOW()`,
        [JSON.stringify(images)]
      );
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/api/bgremover/provider — get current API provider ──────────────
  router.get("/api/bgremover/provider", async (_req, res) => {
    try {
      const r = await db.query("SELECT value FROM admin_settings WHERE `key`='bgremover_provider'");
      res.json({ success: true, provider: r.rows[0]?.value ?? 'removebg' });
    } catch { res.status(500).json({ success: false }); }
  });

  // ── PUT /admin/api/bgremover/provider — set API provider ─────────────────────
  router.put("/api/bgremover/provider", async (req, res) => {
    try {
      const provider = (req.body && req.body.provider === 'free') ? 'free' : 'removebg';
      await db.query(
        `INSERT INTO admin_settings (\`key\`, value) VALUES ('bgremover_provider',?)
         ON DUPLICATE KEY UPDATE value=VALUES(value)`,
        [provider]
      );
      res.json({ success: true, provider });
    } catch (err) {
      console.error('[bgremover/provider PUT]', err?.message);
      res.status(500).json({ success: false, error: err?.message });
    }
  });

  // ── GET /admin/api/static-templates — list all static templates with overrides ──
  router.get("/api/static-templates", async (_req, res) => {
    try {
      const overrides = (await db.query("SELECT * FROM template_overrides")).rows;
      const overrideMap = Object.fromEntries(overrides.map(o => [o.template_id, o]));
      const merged = TEMPLATES.map(t => {
        const ov = overrideMap[t.id] || {};
        return {
          id: t.id,
          title:         ov.title          ?? t.title,
          description:   ov.description    ?? t.description,
          previewImage:  ov.preview_image_url ?? t.previewImage,
          isAvailable:   ov.is_available   != null ? ov.is_available : t.isAvailable,
          badge:              ov.badge               ?? t.badge,
          category:           t.category,
          hasOverride:        !!overrideMap[t.id],
          backgroundImageUrl: ov.background_image_url ?? null,
        };
      });
      res.json({ success: true, templates: merged });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── PUT /admin/api/static-templates/:id — upsert override fields ──────────────
  router.put("/api/static-templates/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const { title, description, badge, isAvailable } = req.body || {};
      await db.query(`
        INSERT INTO template_overrides (template_id, title, description, badge, is_available, updated_at)
        VALUES (?,?,?,?,?,NOW())
        ON DUPLICATE KEY UPDATE
          title        = COALESCE(VALUES(title),        title),
          description  = COALESCE(VALUES(description),  description),
          badge        = COALESCE(VALUES(badge),         badge),
          is_available = COALESCE(VALUES(is_available),  is_available),
          updated_at   = NOW()
      `, [id, title || null, description || null, badge || null, isAvailable != null ? isAvailable : null]);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── POST /admin/api/static-templates/:id/image — upload preview image ────────
  router.post("/api/static-templates/:id/image", tplUpload.single("image"), async (req, res) => {
    try {
      const { id } = req.params;
      if (!req.file) return res.status(400).json({ success: false, error: "No file uploaded" });
      const imageUrl = `/images/templates/uploads/${req.file.filename}`;
      await db.query(`
        INSERT INTO template_overrides (template_id, preview_image_url, updated_at)
        VALUES (?,?,NOW())
        ON DUPLICATE KEY UPDATE
          preview_image_url = VALUES(preview_image_url),
          updated_at        = NOW()
      `, [id, imageUrl]);
      res.json({ success: true, imageUrl });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── POST /admin/api/static-templates/:id/background — upload background ──────
  router.post("/api/static-templates/:id/background", tplUpload.single("image"), async (req, res) => {
    try {
      const { id } = req.params;
      if (!req.file) return res.status(400).json({ success: false, error: "No file uploaded" });
      const imageUrl = `/images/templates/uploads/${req.file.filename}`;
      await db.query(`
        INSERT INTO template_overrides (template_id, background_image_url, updated_at)
        VALUES (?,?,NOW())
        ON DUPLICATE KEY UPDATE
          background_image_url = VALUES(background_image_url),
          updated_at           = NOW()
      `, [id, imageUrl]);
      res.json({ success: true, imageUrl });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── DELETE /admin/api/static-templates/:id/background — remove background ────
  router.delete("/api/static-templates/:id/background", async (req, res) => {
    try {
      const { id } = req.params;
      await db.query(`
        INSERT INTO template_overrides (template_id, background_image_url, updated_at) VALUES (?,NULL,NOW())
        ON DUPLICATE KEY UPDATE background_image_url=NULL, updated_at=NOW()
      `, [id]);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/preview/:slug — admin live preview with sample data ───────────
  const PREVIEW_SAMPLE = {
    fullName:       "Alex Johnson",
    roleTitle:      "Senior Software Engineer",
    email:          "alex.johnson@email.com",
    phone:          "+91 98765 43210",
    location:       "Bangalore, India",
    summary:        "Results-driven software engineer with 6+ years building scalable web applications and APIs. Expert in full-stack development, cloud infrastructure, and agile methodologies.",
    experience:     JSON.stringify([
      { title: "Senior Software Engineer", company: "TechCorp India", dates: "2021 – Present", description: "Led microservices platform handling 10M+ daily requests.\n• Reduced API latency by 40% through Redis caching.\n• Mentored team of 4 junior engineers." },
      { title: "Software Engineer",        company: "StartupHub",     dates: "2018 – 2021",   description: "Built customer-facing dashboard with React & Node.js.\n• Integrated Razorpay, increasing conversion by 25%." },
    ]),
    education:      "B.Tech Computer Science | IIT Bangalore | 2018\nMinor in Data Science | CGPA 8.7/10",
    skills:         "React\nNode.js\nPostgreSQL\nDocker\nAWS\nPython\nKubernetes",
    languages:      "English\nHindi\nKannada",
    certifications: "AWS Solutions Architect – Professional (2023)\nGoogle Cloud Professional Developer (2022)",
    technologies:   "Frontend: React, TypeScript, Tailwind CSS\nBackend: Node.js, Python, FastAPI\nDatabase: PostgreSQL, Redis, MongoDB",
    achievements:   "Open-source library with 3,000+ GitHub stars\nPromoted to Senior in 18 months\nHackathon Winner – Google DevFest 2023",
    projects:       "SmartBudget | Tech: React, Node, PostgreSQL | smartbudget.app\nAI-powered finance tracker – 5,000 users in 3 months.",
    volunteering:   "Code Mentor – Google DSC (2022–Present)\nOpen Source Contributor – Mozilla Firefox",
    references:     "Dr. Priya Sharma\nIIT Bangalore\n+91 80000 12345",
    awards:         "Employee of the Year 2023 – TechCorp\nBest Innovation Award 2022",
    hobbies:        "Photography\nChess\nRock Climbing\nOpen Source",
    training:       "Machine Learning Specialization – Coursera, 2023\nFull-Stack Development – freeCodeCamp",
    publications:   "Microservices at Scale – Medium, 2023\nBuilding Resilient APIs – Dev.to, 2022",
    portfolioUrl:   "https://alexjohnson.dev",
    githubUrl:      "https://github.com/alexjohnson",
    linkedinUrl:    "https://linkedin.com/in/alexjohnson",
  };

  router.get("/preview/:slug", async (req, res) => {
    try {
      const { slug } = req.params;
      const tplRow = await db.query("SELECT * FROM admin_templates WHERE slug=?", [slug]);
      const adminTemplateConfig = tplRow.rows[0] || null;
      if (!adminTemplateConfig) return res.status(404).send("Template not found");

      const secRes = await db.query(
        "SELECT section_key, is_enabled, sort_order, placement, display_type, label_override FROM admin_template_sections WHERE template_id=? ORDER BY sort_order",
        [adminTemplateConfig.id]
      );
      const templateSections = secRes.rows;

      res.render("resume-preview", {
        data:               PREVIEW_SAMPLE,
        template:           slug,
        qrCodeDataUrl:      null,
        displayPrice:       0,
        adminTemplateConfig,
        templateSections,
        isAdminPreview:     true,
        isCompact:          req.query.compact === "1",
        bgImageUrl:         adminTemplateConfig.background_image_url || null,
      });
    } catch (err) {
      res.status(500).send("Preview error: " + err.message);
    }
  });

  // ── Coupons CRUD ──────────────────────────────────────────────────────────
  router.get("/api/coupons", async (req, res) => {
    try {
      const result = await db.query("SELECT * FROM coupons ORDER BY created_at DESC");
      res.json({ success: true, coupons: result.rows });
    } catch { res.status(500).json({ success: false }); }
  });

  router.post("/api/coupons", async (req, res) => {
    try {
      const { code, description, discount_type, discount_value, min_amount, max_uses, first_time_only, expires_at } = req.body;
      if (!code || !discount_type || discount_value == null) {
        return res.status(400).json({ success: false, error: "code, discount_type and discount_value are required." });
      }
      const upper = String(code).trim().toUpperCase();
      const result = await db.query(
        `INSERT INTO coupons (code, description, discount_type, discount_value, min_amount, max_uses, first_time_only, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          upper,
          description || null,
          discount_type,
          Number(discount_value),
          Number(min_amount) || 0,
          Number(max_uses) || 0,
          first_time_only === true || first_time_only === "true",
          expires_at || null,
        ]
      );
      const newCoupon = await db.query("SELECT * FROM coupons WHERE id=?", [result.insertId]);
      res.json({ success: true, coupon: newCoupon.rows[0] });
    } catch (err) {
      if (err.code === "23505") return res.status(400).json({ success: false, error: "A coupon with that code already exists." });
      res.status(500).json({ success: false, error: "Server error." });
    }
  });

  router.put("/api/coupons/:id/toggle", async (req, res) => {
    try {
      const cid = parseInt(req.params.id, 10);
      const curCoupon = await db.query("SELECT is_active FROM coupons WHERE id=?", [cid]);
      if (!curCoupon.rows[0]) return res.status(404).json({ success: false });
      const newActive = !curCoupon.rows[0].is_active;
      await db.query("UPDATE coupons SET is_active=? WHERE id=?", [newActive, cid]);
      const updatedCoupon = await db.query("SELECT * FROM coupons WHERE id=?", [cid]);
      res.json({ success: true, coupon: updatedCoupon.rows[0] });
    } catch { res.status(500).json({ success: false }); }
  });

  router.delete("/api/coupons/:id", async (req, res) => {
    try {
      await db.query("DELETE FROM coupons WHERE id=?", [parseInt(req.params.id, 10)]);
      res.json({ success: true });
    } catch { res.status(500).json({ success: false }); }
  });

  // ── Ads master on/off setting ─────────────────────────────────────────────
  // ── Env / API key management ──────────────────────────────────────────────
  const ENV_WHITELIST = [
    'RAZORPAY_KEY_ID', 'RAZORPAY_KEY_SECRET', 'RAZORPAY_WEBHOOK_SECRET',
    'BASE_URL', 'OPENAI_API_KEY',
    'EMAIL_HOST', 'EMAIL_PORT', 'EMAIL_USER', 'EMAIL_PASS',
  ];

  router.get("/api/env-settings", async (req, res) => {
    try {
      const envKeys = ENV_WHITELIST.map(k => `env_${k.toLowerCase()}`);
      const placeholders = envKeys.map(() => '?').join(',');
      const rows = await db.query(
        `SELECT \`key\`, value FROM admin_settings WHERE \`key\` IN (${placeholders})`,
        envKeys
      );
      const saved = {};
      for (const r of rows.rows) saved[r.key] = r.value;
      const result = ENV_WHITELIST.reduce((acc, k) => {
        acc[k] = saved[`env_${k.toLowerCase()}`] ?? process.env[k] ?? '';
        return acc;
      }, {});
      res.json({ success: true, settings: result });
    } catch { res.status(500).json({ success: false }); }
  });

  router.patch("/api/env-settings", async (req, res) => {
    try {
      const updates = req.body || {};
      for (const [rawKey, val] of Object.entries(updates)) {
        const key = rawKey.toUpperCase();
        if (!ENV_WHITELIST.includes(key)) continue;
        const dbKey = `env_${key.toLowerCase()}`;
        const strVal = String(val ?? '').trim();
        await db.query(
          `INSERT INTO admin_settings (\`key\`, value, updated_at) VALUES (?,?,NOW())
           ON DUPLICATE KEY UPDATE value=VALUES(value), updated_at=NOW()`,
          [dbKey, strVal]
        );
        if (strVal) process.env[key] = strVal;
      }
      res.json({ success: true });
    } catch { res.status(500).json({ success: false }); }
  });

  router.get("/api/ads/settings", async (req, res) => {
    try {
      const r = await db.query("SELECT value FROM admin_settings WHERE `key`='ads_enabled'");
      res.json({ success: true, adsEnabled: (r.rows[0]?.value ?? 'true') === 'true' });
    } catch { res.status(500).json({ success: false }); }
  });

  router.put("/api/ads/settings", async (req, res) => {
    try {
      const enabled = req.body.enabled !== false;
      await db.query("UPDATE admin_settings SET value=? WHERE `key`='ads_enabled'", [enabled ? 'true' : 'false']);
      res.json({ success: true, adsEnabled: enabled });
    } catch { res.status(500).json({ success: false }); }
  });

  // ── Ads CRUD ──────────────────────────────────────────────────────────────
  router.get("/api/ads", async (req, res) => {
    try {
      const result = await db.query("SELECT * FROM ads ORDER BY id DESC");
      res.json({ success: true, ads: result.rows });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  router.post("/api/ads", adUpload.single("image"), async (req, res) => {
    const { slot, title, link_url } = req.body;
    if (!slot || !link_url) return res.status(400).json({ success: false, message: "slot and link_url required" });
    const image_url = req.file ? `/uploads/ads/${req.file.filename}` : null;
    try {
      const result = await db.query(
        "INSERT INTO ads (slot, title, image_url, link_url) VALUES (?,?,?,?)",
        [slot, title || null, image_url, link_url]
      );
      const newAd = await db.query("SELECT * FROM ads WHERE id=?", [result.insertId]);
      res.json({ success: true, ad: newAd.rows[0] });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  router.put("/api/ads/:id/toggle", async (req, res) => {
    try {
      const aid = parseInt(req.params.id, 10);
      const curAd = await db.query("SELECT is_active FROM ads WHERE id=?", [aid]);
      if (!curAd.rows[0]) return res.status(404).json({ success: false });
      const newAdActive = !curAd.rows[0].is_active;
      await db.query("UPDATE ads SET is_active=? WHERE id=?", [newAdActive, aid]);
      const updatedAd = await db.query("SELECT * FROM ads WHERE id=?", [aid]);
      res.json({ success: true, ad: updatedAd.rows[0] });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  router.delete("/api/ads/:id", async (req, res) => {
    try {
      const delId = parseInt(req.params.id, 10);
      const row = await db.query("SELECT image_url FROM ads WHERE id=?", [delId]);
      await db.query("DELETE FROM ads WHERE id=?", [delId]);
      if (row.rows[0]?.image_url) {
        const filePath = path.join(__dirname, "..", "public", row.rows[0].image_url);
        fs.unlink(filePath, () => {});
      }
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  // ── Investor Management ─────────────────────────────────────────────────────

  // GET /admin/api/investor-requests — list all requests
  router.get("/api/investor-requests", async (req, res) => {
    try {
      const rows = await db.query(
        `SELECT ir.*, u.name, u.email
         FROM investor_requests ir JOIN users u ON u.id = ir.user_id
         ORDER BY ir.created_at DESC`
      );
      res.json({ success: true, requests: rows.rows });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  // PATCH /admin/api/investor-requests/:id/approve
  router.patch("/api/investor-requests/:id/approve", async (req, res) => {
    try {
      const { id } = req.params;
      const r = await db.query(
        "SELECT user_id FROM investor_requests WHERE id=?",
        [id]
      );
      if (!r.rows[0]) return res.status(404).json({ success: false });
      await db.query("UPDATE investor_requests SET status='approved', updated_at=NOW() WHERE id=?", [id]);
      await db.query("UPDATE users SET investor_approved=true WHERE id=?", [r.rows[0].user_id]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  // PATCH /admin/api/investor-requests/:id/reject
  router.patch("/api/investor-requests/:id/reject", async (req, res) => {
    try {
      const { id } = req.params;
      const { admin_note } = req.body;
      await db.query(
        "UPDATE investor_requests SET status='rejected', admin_note=?, updated_at=NOW() WHERE id=?",
        [admin_note || null, id]
      );
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  // DELETE /admin/api/investor-requests/:id — remove a request entirely
  router.delete("/api/investor-requests/:id", async (req, res) => {
    try {
      await db.query("DELETE FROM investor_requests WHERE id=?", [req.params.id]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  // GET /admin/api/investments — list all investments
  router.get("/api/investments", async (req, res) => {
    try {
      const rows = await db.query(
        `SELECT i.*, u.name, u.email
         FROM investments i JOIN users u ON u.id = i.user_id
         ORDER BY i.created_at DESC`
      );
      res.json({ success: true, investments: rows.rows });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  // POST /admin/api/investments/manual — admin manually records an investment
  router.post("/api/investments/manual", async (req, res) => {
    try {
      const { user_id, amount, payment_ref, valuation: valuationOverride } = req.body;
      if (!user_id || !amount) return res.status(400).json({ success: false, message: 'user_id and amount required' });
      const cfgRows = await db.query(
        "SELECT `key`, value FROM admin_settings WHERE `key` IN ('investment_equity','investment_valuation')"
      );
      const cfg = {};
      for (const r of cfgRows.rows) cfg[r.key] = parseFloat(r.value);
      const valuation = valuationOverride ? parseFloat(valuationOverride) : (cfg.investment_valuation || 125000);
      const totalEquity = cfg.investment_equity || 40;
      const soldRes = await db.query("SELECT COALESCE(SUM(equity_percent),0) AS sold FROM investments WHERE user_id!=?", [user_id]);
      const sold = parseFloat(soldRes.rows[0].sold) || 0;
      const remaining = parseFloat((totalEquity - sold).toFixed(2));
      const equityPercent = parseFloat(((parseFloat(amount) / valuation) * 100).toFixed(2));
      if (equityPercent > remaining) {
        return res.json({ success: false, message: `Only ${remaining.toFixed(2)}% equity remaining` });
      }
      const paymentId = payment_ref || `MANUAL-${Date.now()}`;
      await db.query(
        `INSERT IGNORE INTO investments (user_id, amount, equity_percent, valuation, payment_id)
         VALUES (?, ?, ?, ?, ?)`,
        [user_id, parseFloat(amount), equityPercent, valuation, paymentId]
      );
      // Only set role='investor' if not already admin or subadmin
      await db.query("UPDATE users SET role='investor' WHERE id=? AND role NOT IN ('admin','subadmin')", [user_id]);
      res.json({ success: true, equityPercent });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // PATCH /admin/api/investments/:id — admin updates an existing investment amount
  router.patch("/api/investments/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const { amount, payment_ref } = req.body;
      if (!amount) return res.status(400).json({ success: false, message: 'amount required' });
      const inv = await db.query("SELECT * FROM investments WHERE id=?", [id]);
      if (!inv.rows[0]) return res.status(404).json({ success: false });
      const valuation = parseFloat(inv.rows[0].valuation);
      const equityPercent = parseFloat(((parseFloat(amount) / valuation) * 100).toFixed(2));
      const updates = ["amount=?", "equity_percent=?"];
      const params = [parseFloat(amount), equityPercent];
      if (payment_ref) { updates.push("payment_id=?"); params.push(payment_ref); }
      params.push(id);
      await db.query(`UPDATE investments SET ${updates.join(', ')} WHERE id=?`, params);
      res.json({ success: true, equityPercent });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // GET /admin/api/investment-config — read current config
  router.get("/api/investment-config", async (req, res) => {
    try {
      const rows = await db.query(
        "SELECT `key`, value FROM admin_settings WHERE `key` IN ('investment_amount','investment_equity','investment_valuation')"
      );
      const cfg = {};
      for (const r of rows.rows) cfg[r.key] = parseFloat(r.value);
      res.json({
        amount:    cfg.investment_amount    || 50000,
        equity:    cfg.investment_equity    || 40,
        valuation: cfg.investment_valuation || 125000,
      });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  // PATCH /admin/api/investment-config — update investment amount/equity/valuation
  router.patch("/api/investment-config", async (req, res) => {
    try {
      const { amount, equity, valuation } = req.body;
      const updates = [];
      if (amount   != null) updates.push(db.query("INSERT INTO admin_settings(`key`,value) VALUES('investment_amount',?) ON DUPLICATE KEY UPDATE value=VALUES(value)", [String(amount)]));
      if (equity   != null) updates.push(db.query("INSERT INTO admin_settings(`key`,value) VALUES('investment_equity',?) ON DUPLICATE KEY UPDATE value=VALUES(value)", [String(equity)]));
      if (valuation!= null) updates.push(db.query("INSERT INTO admin_settings(`key`,value) VALUES('investment_valuation',?) ON DUPLICATE KEY UPDATE value=VALUES(value)", [String(valuation)]));
      await Promise.all(updates);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  // ── Wallet admin endpoints ─────────────────────────────────────────────────

  // GET /admin/api/wallet/users — paginated users with wallet balance
  router.get("/api/wallet/users", async (req, res) => {
    try {
      const page  = Math.max(1, parseInt(req.query.page)  || 1);
      const limit = Math.min(50, parseInt(req.query.limit) || 20);
      const offset = (page - 1) * limit;
      const search = req.query.search ? `%${req.query.search}%` : null;

      let where = "WHERE u.role NOT IN ('admin','subadmin')";
      const params = [];
      if (search) { where += " AND (u.name LIKE ? OR u.email LIKE ?)"; params.push(search, search); }

      const countRes = await db.query(`SELECT COUNT(*) AS count FROM users u ${where}`, params);
      const total = parseInt(countRes.rows[0]?.count) || 0;

      const rows = await db.query(
        `SELECT u.id, u.name, u.email, u.wallet_balance,
                (SELECT COUNT(*) FROM users r WHERE r.referred_by = u.id) AS referral_count
         FROM users u ${where}
         ORDER BY u.wallet_balance DESC LIMIT ? OFFSET ?`,
        [...params, limit, offset]
      );
      res.json({ success: true, users: rows.rows, total, page, limit });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // POST /admin/api/wallet/adjust — credit or debit a user's wallet
  router.post("/api/wallet/adjust", async (req, res) => {
    try {
      const { userId, amount, type, reason } = req.body;
      if (!userId || !amount || !['credit','debit'].includes(type)) {
        return res.status(400).json({ success: false, message: "userId, amount, and type (credit/debit) are required" });
      }
      const amt = parseFloat(amount);
      if (isNaN(amt) || amt <= 0) return res.status(400).json({ success: false, message: "Invalid amount" });

      if (type === 'credit') {
        await db.query("UPDATE users SET wallet_balance = wallet_balance + ? WHERE id=?", [amt, userId]);
      } else {
        await db.query("UPDATE users SET wallet_balance = GREATEST(0, wallet_balance - ?) WHERE id=?", [amt, userId]);
      }
      await db.query(
        "INSERT INTO wallet_transactions (user_id, amount, type, reason) VALUES (?,?,?,?)",
        [userId, amt, type, reason || 'admin_adjustment']
      );
      const updated = await db.query("SELECT wallet_balance FROM users WHERE id=?", [userId]);
      res.json({ success: true, newBalance: parseFloat(updated.rows[0]?.wallet_balance) || 0 });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // GET /admin/api/wallet/transactions/:userId — transaction history for a user
  router.get("/api/wallet/transactions/:userId", async (req, res) => {
    try {
      const userId = parseInt(req.params.userId);
      const rows = await db.query(
        "SELECT * FROM wallet_transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 50",
        [userId]
      );
      res.json({ success: true, transactions: rows.rows });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // ── Subscription Admin Routes ─────────────────────────────────────────────

  // List all plans
  router.get("/api/subscription-plans", async (req, res) => {
    try {
      const result = await db.query("SELECT * FROM subscription_plans ORDER BY duration_days ASC");
      res.json({ success: true, plans: result.rows });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // Create new plan
  router.post("/api/subscription-plans", async (req, res) => {
    try {
      const { name, duration_days, price, description } = req.body;
      if (!name || !duration_days || !price) {
        return res.status(400).json({ success: false, message: "Name, duration and price are required" });
      }
      await db.query(
        "INSERT INTO subscription_plans (name, duration_days, price, description) VALUES (?,?,?,?)",
        [name, parseInt(duration_days), parseFloat(price), description || null]
      );
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // Update plan (price, duration, name, description, is_active)
  router.patch("/api/subscription-plans/:id", async (req, res) => {
    try {
      const { name, duration_days, price, description, is_active } = req.body;
      await db.query(
        `UPDATE subscription_plans SET
          name = COALESCE(?, name),
          duration_days = COALESCE(?, duration_days),
          price = COALESCE(?, price),
          description = COALESCE(?, description),
          is_active = COALESCE(?, is_active)
         WHERE id = ?`,
        [name||null, duration_days ? parseInt(duration_days) : null,
         price ? parseFloat(price) : null, description||null,
         is_active !== undefined ? is_active : null, req.params.id]
      );
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // List all user subscriptions with filters
  router.get("/api/subscriptions", async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = 20;
      const offset = (page - 1) * limit;
      const status = req.query.status || null;

      let where = status ? "WHERE us.status = ?" : "";
      const params = status ? [status, limit, offset] : [limit, offset];

      const result = await db.query(
        `SELECT us.*, u.name AS user_name, u.email AS user_email, sp.name AS plan_name
         FROM user_subscriptions us
         JOIN users u ON us.user_id = u.id
         JOIN subscription_plans sp ON us.plan_id = sp.id
         ${where}
         ORDER BY us.created_at DESC LIMIT ? OFFSET ?`,
        params
      );
      const countResult = await db.query(
        `SELECT COUNT(*) AS total FROM user_subscriptions us ${where}`,
        status ? [status] : []
      );
      res.json({ success: true, subscriptions: result.rows, total: countResult.rows[0].total });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // Grant free subscription to a user
  router.post("/api/subscriptions/grant", async (req, res) => {
    try {
      const { userId, planId } = req.body;
      const plan = await db.query("SELECT * FROM subscription_plans WHERE id = ?", [planId]);
      if (!plan.rows.length) return res.status(404).json({ success: false, message: "Plan not found" });
      const p = plan.rows[0];
      const endDate = new Date();
      endDate.setDate(endDate.getDate() + p.duration_days);
      await db.query(
        `INSERT INTO user_subscriptions (user_id, plan_id, amount, status, end_date, granted_by_admin)
         VALUES (?, ?, 0, 'active', ?, true)`,
        [userId, planId, endDate]
      );
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // Subscription analytics stats
  router.get("/api/subscriptions/stats", async (req, res) => {
    try {
      const [activeCount, totalRevenue, planBreakdown] = await Promise.all([
        db.query("SELECT COUNT(*) AS count FROM user_subscriptions WHERE status='active' AND end_date >= NOW()"),
        db.query("SELECT COALESCE(SUM(amount),0) AS total FROM user_subscriptions WHERE granted_by_admin=false"),
        db.query(
          `SELECT sp.name, sp.duration_days, COUNT(*) AS count, COALESCE(SUM(us.amount),0) AS revenue
           FROM user_subscriptions us JOIN subscription_plans sp ON us.plan_id=sp.id
           GROUP BY sp.id, sp.name, sp.duration_days`
        ),
      ]);
      res.json({
        success: true,
        activeSubscribers: activeCount.rows[0].count,
        totalRevenue: totalRevenue.rows[0].total,
        planBreakdown: planBreakdown.rows,
      });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // ── PaySetu Admin Routes ─────────────────────────────────────────────────────

  // GET /admin/api/paysetu/stats
  router.get("/api/paysetu/stats", async (req, res) => {
    try {
      const [rcTotal, rcSuccess, rcFailed, rcVolume, bbpsTotal, bbpsSuccess, bbpsFailed, bbpsVolume, billers] = await Promise.all([
        db.query("SELECT COUNT(*) AS c FROM recharge_transactions"),
        db.query("SELECT COUNT(*) AS c FROM recharge_transactions WHERE status='success'"),
        db.query("SELECT COUNT(*) AS c FROM recharge_transactions WHERE status='failed'"),
        db.query("SELECT COALESCE(SUM(amount),0) AS t FROM recharge_transactions WHERE status='success'"),
        db.query("SELECT COUNT(*) AS c FROM bbps_transactions"),
        db.query("SELECT COUNT(*) AS c FROM bbps_transactions WHERE status='success'"),
        db.query("SELECT COUNT(*) AS c FROM bbps_transactions WHERE status='failed'"),
        db.query("SELECT COALESCE(SUM(amount),0) AS t FROM bbps_transactions WHERE status='success'"),
        db.query("SELECT COUNT(*) AS c FROM billers WHERE is_active=1"),
      ]);
      res.json({
        success: true,
        recharge:  { total: +rcTotal.rows[0].c,   success: +rcSuccess.rows[0].c,  failed: +rcFailed.rows[0].c,  volume: Math.round(+rcVolume.rows[0].t) },
        bbps:      { total: +bbpsTotal.rows[0].c, success: +bbpsSuccess.rows[0].c, failed: +bbpsFailed.rows[0].c, volume: Math.round(+bbpsVolume.rows[0].t) },
        billers:   +billers.rows[0].c,
      });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // GET /admin/api/paysetu/transactions — unified paginated list
  router.get("/api/paysetu/transactions", async (req, res) => {
    try {
      const page   = Math.max(1, parseInt(req.query.page)  || 1);
      const limit  = Math.min(50, parseInt(req.query.limit) || 20);
      const offset = (page - 1) * limit;
      const filter = req.query.filter || "all"; // all | recharge | bbps | failed
      const search = req.query.search || "";

      let rows = [], total = 0;
      const likeSearch = `%${search}%`;

      if (filter === "bbps") {
        const where = search ? "AND (u.name LIKE ? OR u.email LIKE ? OR t.biller_name LIKE ? OR t.customer_number LIKE ?)" : "";
        const params = search ? [likeSearch, likeSearch, likeSearch, likeSearch] : [];
        const countRes = await db.query(`SELECT COUNT(*) AS c FROM bbps_transactions t JOIN users u ON u.id=t.user_id ${where ? 'WHERE '+where.slice(4) : ''}`, params);
        total = +countRes.rows[0].c;
        const res2 = await db.query(
          `SELECT t.*, u.name AS user_name, u.email AS user_email, 'bbps' AS txn_type FROM bbps_transactions t JOIN users u ON u.id=t.user_id ${where ? 'WHERE '+where.slice(4) : ''} ORDER BY t.created_at DESC LIMIT ? OFFSET ?`,
          [...params, limit, offset]
        );
        rows = res2.rows;
      } else if (filter === "recharge") {
        const where = search ? "AND (u.name LIKE ? OR u.email LIKE ? OR t.operator LIKE ? OR t.mobile LIKE ?)" : "";
        const params = search ? [likeSearch, likeSearch, likeSearch, likeSearch] : [];
        const countRes = await db.query(`SELECT COUNT(*) AS c FROM recharge_transactions t JOIN users u ON u.id=t.user_id ${where ? 'WHERE '+where.slice(4) : ''}`, params);
        total = +countRes.rows[0].c;
        const res2 = await db.query(
          `SELECT t.*, u.name AS user_name, u.email AS user_email, 'recharge' AS txn_type FROM recharge_transactions t JOIN users u ON u.id=t.user_id ${where ? 'WHERE '+where.slice(4) : ''} ORDER BY t.created_at DESC LIMIT ? OFFSET ?`,
          [...params, limit, offset]
        );
        rows = res2.rows;
      } else if (filter === "pending") {
        const rcWhere = search ? "AND (u.name LIKE ? OR u.email LIKE ? OR t.operator LIKE ?)" : "";
        const rcParams = search ? [likeSearch, likeSearch, likeSearch] : [];
        const countRes = await db.query(`SELECT COUNT(*) AS c FROM recharge_transactions t JOIN users u ON u.id=t.user_id WHERE t.status='pending' ${rcWhere}`, rcParams);
        total = +countRes.rows[0].c;
        const res2 = await db.query(
          `SELECT t.*, u.name AS user_name, u.email AS user_email, 'recharge' AS txn_type FROM recharge_transactions t JOIN users u ON u.id=t.user_id WHERE t.status='pending' ${rcWhere} ORDER BY t.created_at DESC LIMIT ? OFFSET ?`,
          [...rcParams, limit, offset]
        );
        rows = res2.rows;
      } else if (filter === "failed") {
        const rcWhere = search ? "AND (u.name LIKE ? OR u.email LIKE ? OR t.operator LIKE ?)" : "";
        const rcParams = search ? [likeSearch, likeSearch, likeSearch] : [];
        const bbWhere = search ? "AND (u.name LIKE ? OR u.email LIKE ? OR t.biller_name LIKE ?)" : "";
        const bbParams = search ? [likeSearch, likeSearch, likeSearch] : [];
        const [rcRes, bbRes] = await Promise.all([
          db.query(`SELECT t.*, u.name AS user_name, u.email AS user_email, 'recharge' AS txn_type FROM recharge_transactions t JOIN users u ON u.id=t.user_id WHERE t.status='failed' ${rcWhere} ORDER BY t.created_at DESC LIMIT ?`, [...rcParams, limit]),
          db.query(`SELECT t.*, u.name AS user_name, u.email AS user_email, 'bbps' AS txn_type FROM bbps_transactions t JOIN users u ON u.id=t.user_id WHERE t.status='failed' ${bbWhere} ORDER BY t.created_at DESC LIMIT ?`, [...bbParams, limit]),
        ]);
        rows = [...rcRes.rows, ...bbRes.rows].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, limit);
        total = rows.length;
      } else {
        // all — union
        const [rcRes, bbRes] = await Promise.all([
          db.query("SELECT t.*, u.name AS user_name, u.email AS user_email, 'recharge' AS txn_type FROM recharge_transactions t JOIN users u ON u.id=t.user_id ORDER BY t.created_at DESC LIMIT ?", [limit]),
          db.query("SELECT t.*, u.name AS user_name, u.email AS user_email, 'bbps' AS txn_type FROM bbps_transactions t JOIN users u ON u.id=t.user_id ORDER BY t.created_at DESC LIMIT ?", [limit]),
        ]);
        rows = [...rcRes.rows, ...bbRes.rows].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, limit);
        const [rcCount, bbCount] = await Promise.all([
          db.query("SELECT COUNT(*) AS c FROM recharge_transactions"),
          db.query("SELECT COUNT(*) AS c FROM bbps_transactions"),
        ]);
        total = +rcCount.rows[0].c + +bbCount.rows[0].c;
      }

      res.json({ success: true, rows, total, page, limit });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // POST /admin/api/paysetu/refund — manual wallet refund for a failed transaction
  router.post("/api/paysetu/refund", async (req, res) => {
    try {
      const { txn_id, txn_type, reason } = req.body;
      if (!txn_id || !txn_type || !['recharge','bbps'].includes(txn_type)) {
        return res.json({ success: false, message: 'Invalid request.' });
      }
      const table = txn_type === 'recharge' ? 'recharge_transactions' : 'bbps_transactions';
      const txnRes = await db.query(`SELECT * FROM ${table} WHERE id=?`, [txn_id]);
      const txn = txnRes.rows[0];
      if (!txn) return res.json({ success: false, message: 'Transaction not found.' });
      if (txn.status !== 'failed') return res.json({ success: false, message: 'Only failed transactions can be manually refunded.' });

      // Credit wallet
      await db.query("UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?", [txn.amount, txn.user_id]);
      await db.query("INSERT INTO wallet_transactions (user_id, amount, type, reason) VALUES (?,?,?,?)", [txn.user_id, txn.amount, 'credit', reason || `Admin refund for ${txn_type} txn #${txn_id}`]);
      await db.query(`UPDATE ${table} SET status='failed', external_ref=CONCAT(IFNULL(external_ref,''),'[admin_refunded]') WHERE id=?`, [txn_id]);

      res.json({ success: true, message: `₹${txn.amount} refunded to user #${txn.user_id}` });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // DELETE /admin/api/paysetu/transactions/:id — permanently remove a transaction
  router.delete("/api/paysetu/transactions/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const type = req.query.type; // 'recharge' or 'bbps'
      if (!id || !['recharge', 'bbps'].includes(type)) {
        return res.status(400).json({ success: false, message: 'Valid id and type (recharge|bbps) required.' });
      }
      const table = type === 'recharge' ? 'recharge_transactions' : 'bbps_transactions';
      const result = await db.query(`DELETE FROM ${table} WHERE id = ?`, [id]);
      if ((result.affectedRows ?? result.rowCount ?? 0) === 0) {
        return res.status(404).json({ success: false, message: 'Transaction not found.' });
      }
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // POST /admin/api/paysetu/reset-pin — clear wallet PIN for a user
  router.post("/api/paysetu/reset-pin", async (req, res) => {
    try {
      const { user_id } = req.body;
      if (!user_id) return res.json({ success: false, message: 'user_id required.' });
      await db.query("UPDATE users SET wallet_pin = NULL WHERE id = ?", [user_id]);
      res.json({ success: true, message: `Wallet PIN cleared for user #${user_id}. They must set a new PIN on next payment.` });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // GET /admin/api/paysetu/billers — list all billers
  router.get("/api/paysetu/billers", async (req, res) => {
    try {
      const rows = await db.query("SELECT * FROM billers ORDER BY category, name");
      res.json({ success: true, billers: rows.rows });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // POST /admin/api/paysetu/billers — add biller
  router.post("/api/paysetu/billers", async (req, res) => {
    try {
      const { biller_id, name, category } = req.body;
      if (!biller_id || !name || !category) return res.json({ success: false, message: 'biller_id, name, and category are required.' });
      await db.query("INSERT INTO billers (biller_id, name, category) VALUES (?,?,?)", [biller_id.trim().toUpperCase(), name.trim(), category]);
      res.json({ success: true });
    } catch (err) {
      if (err.message?.includes('Duplicate')) return res.json({ success: false, message: 'Biller ID already exists.' });
      res.status(500).json({ success: false, message: err.message });
    }
  });

  // PUT /admin/api/paysetu/billers/:id — update biller
  router.put("/api/paysetu/billers/:id", async (req, res) => {
    try {
      const { name, category } = req.body;
      await db.query("UPDATE billers SET name=?, category=? WHERE id=?", [name, category, req.params.id]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // PATCH /admin/api/paysetu/billers/:id/toggle — toggle is_active
  router.patch("/api/paysetu/billers/:id/toggle", async (req, res) => {
    try {
      await db.query("UPDATE billers SET is_active = NOT is_active WHERE id=?", [req.params.id]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // DELETE /admin/api/paysetu/billers/:id
  router.delete("/api/paysetu/billers/:id", async (req, res) => {
    try {
      await db.query("DELETE FROM billers WHERE id=?", [req.params.id]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // ── Recharge API Providers ────────────────────────────────────────────────────

  // GET /admin/api/paysetu/providers — list all with masked keys
  router.get("/api/paysetu/providers", async (req, res) => {
    try {
      const rows = await db.query(
        "SELECT id, provider_key, display_name, api_key, api_secret, is_active FROM recharge_api_providers ORDER BY id"
      );
      const providers = rows.rows.map(p => ({
        id:           p.id,
        provider_key: p.provider_key,
        display_name: p.display_name,
        is_active:    p.is_active,
        has_key:      !!p.api_key,
        has_secret:   !!p.api_secret,
        api_key_masked:    p.api_key    ? p.api_key.slice(0,6)    + "••••••" + p.api_key.slice(-4)    : null,
        api_secret_masked: p.api_secret ? p.api_secret.slice(0,4) + "••••••" + p.api_secret.slice(-2) : null,
      }));
      res.json({ success: true, providers });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // PUT /admin/api/paysetu/providers/:id — save API key + secret
  router.put("/api/paysetu/providers/:id", async (req, res) => {
    try {
      const { api_key, api_secret } = req.body || {};
      await db.query(
        "UPDATE recharge_api_providers SET api_key=?, api_secret=? WHERE id=?",
        [api_key || null, api_secret || null, req.params.id]
      );
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // PATCH /admin/api/paysetu/providers/:id/toggle — activate one, deactivate all others
  router.patch("/api/paysetu/providers/:id/toggle", async (req, res) => {
    try {
      const activate = req.body.active === true || req.body.active === 1;
      if (activate) {
        await db.query("UPDATE recharge_api_providers SET is_active=0");
        await db.query("UPDATE recharge_api_providers SET is_active=1 WHERE id=?", [req.params.id]);
      } else {
        await db.query("UPDATE recharge_api_providers SET is_active=0 WHERE id=?", [req.params.id]);
      }
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // GET /admin/api/paysetu/callback-url — return the URL admin must register with femoney24
  router.get("/api/paysetu/callback-url", (req, res) => {
    const secret = process.env.PAYSETU_CALLBACK_SECRET || null;
    const base   = process.env.APP_URL || `${req.protocol}://${req.get("host")}`;
    const url    = secret
      ? `${base}/paysetu/recharge/callback?secret=${secret}`
      : `${base}/paysetu/recharge/callback`;
    res.json({ url, secretSet: !!secret });
  });

  // GET /admin/api/paysetu/provider-balance — check active provider wallet balance
  router.get("/api/paysetu/provider-balance", async (req, res) => {
    try {
      const prov = await db.query(
        "SELECT provider_key, api_key FROM recharge_api_providers WHERE is_active=1 LIMIT 1"
      );
      const p = prov.rows[0];
      if (!p || !p.api_key) {
        return res.json({ success: false, message: "No active provider configured." });
      }
      if (p.provider_key === 'femoney24') {
        const url = `http://femoney24.com/RechargeApi/Balance.aspx?Apitoken=${encodeURIComponent(p.api_key)}`;
        const raw = await fetch(url, { signal: AbortSignal.timeout(10000) }).then(r => r.text());
        let data;
        try { data = JSON.parse(raw); } catch (_) {
          return res.status(502).json({ success: false, message: 'femoney24 returned non-JSON response.' });
        }
        if (data.STATUS === 'SUCCESS') {
          // MESSAGE is formatted like "1,970.10" — strip commas for numeric use
          const balanceStr = String(data.MESSAGE || '0').replace(/,/g, '');
          const balanceNum = parseFloat(balanceStr) || 0;
          return res.json({ success: true, balance: `₹${balanceNum.toLocaleString('en-IN', { minimumFractionDigits: 2 })}`, balanceRaw: balanceNum, provider: 'femoney24' });
        }
        return res.json({ success: false, message: data.MESSAGE || 'Balance check failed' });
      }
      return res.json({ success: false, message: "Balance check not supported for this provider." });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // ── Recharge Plans CRUD ───────────────────────────────────────────────────

  router.get("/api/recharge-plans", async (req, res) => {
    try {
      const { type, operator, circle } = req.query;
      let sql = "SELECT * FROM recharge_plans WHERE 1=1";
      const params = [];
      if (type)     { sql += " AND type=?";     params.push(type); }
      if (operator) { sql += " AND operator=?"; params.push(operator); }
      if (circle)   { sql += " AND circle=?";   params.push(circle); }
      sql += " ORDER BY type, operator, circle, sort_order, amount";
      const result = await db.query(sql, params);
      res.json({ success: true, plans: result.rows });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
  });

  router.post("/api/recharge-plans", async (req, res) => {
    try {
      const { type, operator, amount, validity, description, category, sort_order, circle } = req.body;
      if (!type || !operator || !amount || !validity || !description) {
        return res.status(400).json({ success: false, error: "type, operator, amount, validity, description are required." });
      }
      const circleVal = (circle || 'All India').trim();
      const dup = await db.query(
        "SELECT id FROM recharge_plans WHERE type=? AND operator=? AND amount=? AND validity=? AND circle=?",
        [type, operator, parseInt(amount), validity, circleVal]
      );
      if (dup.rows.length) {
        return res.status(409).json({ success: false, error: "A plan with the same type, operator, amount, validity and circle already exists." });
      }
      const result = await db.query(
        "INSERT INTO recharge_plans (type, operator, amount, validity, description, category, sort_order, circle) VALUES (?,?,?,?,?,?,?,?)",
        [type, operator, parseInt(amount), validity, description, category || "data", parseInt(sort_order) || 0, circleVal]
      );
      res.json({ success: true, id: result.insertId });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
  });

  router.put("/api/recharge-plans/:id", async (req, res) => {
    try {
      const { amount, validity, description, category, sort_order, is_active, circle } = req.body;
      await db.query(
        "UPDATE recharge_plans SET amount=?, validity=?, description=?, category=?, sort_order=?, is_active=?, circle=? WHERE id=?",
        [parseInt(amount), validity, description, category, parseInt(sort_order) || 0, is_active ? 1 : 0, (circle || 'All India').trim(), req.params.id]
      );
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
  });

  router.post("/api/recharge-plans/:id/toggle", async (req, res) => {
    try {
      await db.query("UPDATE recharge_plans SET is_active = 1 - is_active WHERE id=?", [req.params.id]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
  });

  router.delete("/api/recharge-plans/:id", async (req, res) => {
    try {
      await db.query("DELETE FROM recharge_plans WHERE id=?", [req.params.id]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
  });

  router.delete("/api/recharge-plans", async (req, res) => {
    try {
      const { type, operator } = req.query;
      let sql = "DELETE FROM recharge_plans WHERE 1=1";
      const params = [];
      if (type)     { sql += " AND type=?";     params.push(type); }
      if (operator) { sql += " AND operator=?"; params.push(operator); }
      await db.query(sql, params);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
  });

  // ── Check live status of a pending recharge via femoney24 ───────────────────
  router.post("/api/recharge-transactions/:id/check-status", async (req, res) => {
    try {
      const txRow = await db.query(
        "SELECT * FROM recharge_transactions WHERE id=?",
        [req.params.id]
      );
      if (!txRow.rows.length) return res.status(404).json({ success: false, message: "Transaction not found." });
      const txn = txRow.rows[0];

      // Get active femoney24 provider
      const prov = await db.query(
        "SELECT api_key FROM recharge_api_providers WHERE provider_key='femoney24' AND is_active=1 LIMIT 1"
      );
      if (!prov.rows.length || !prov.rows[0].api_key) {
        return res.status(400).json({ success: false, message: "femoney24 not configured or not active." });
      }
      const apiKey = prov.rows[0].api_key;

      const url = `http://femoney24.com/RechargeApi/rechargestatus.aspx?Apitoken=${encodeURIComponent(apiKey)}&ClientId=${txn.id}`;
      const raw  = await fetch(url, { signal: AbortSignal.timeout(10000) }).then(r => r.text());
      let data;
      try { data = JSON.parse(raw); } catch (_) {
        return res.status(502).json({ success: false, message: "femoney24 returned non-JSON response.", raw: raw.slice(0, 200) });
      }

      const rStatus = data.RECHARGESTATUS; // SUCCESS | FAILURE | IN PROCESS

      if (rStatus === 'SUCCESS') {
        await db.query(
          "UPDATE recharge_transactions SET status='success', external_ref=? WHERE id=?",
          [data.OPERATORID || String(txn.id), txn.id]
        );
        return res.json({ success: true, rechargeStatus: 'success', message: 'Transaction marked SUCCESS. Wallet already deducted.' });
      }

      if (rStatus === 'FAILURE' || data.MESSAGE === 'TRANSACTION NOT FOUND') {
        if (txn.status === 'pending') {
          // Refund only if not already refunded
          await db.query("UPDATE recharge_transactions SET status='failed' WHERE id=?", [txn.id]);
          await db.query("UPDATE users SET wallet_balance = wallet_balance + ? WHERE id=?", [txn.amount, txn.user_id]);
          await db.query(
            "INSERT INTO wallet_transactions (user_id, amount, type, reason, ref_id) VALUES (?,?,'credit','recharge_refund',?)",
            [txn.user_id, txn.amount, txn.id]
          );
          return res.json({ success: true, rechargeStatus: 'failed', message: `Transaction FAILED. ₹${txn.amount} refunded to user.` });
        }
        return res.json({ success: true, rechargeStatus: 'failed', message: `Transaction FAILED (status was already: ${txn.status}).` });
      }

      // IN PROCESS — still pending
      return res.json({ success: true, rechargeStatus: 'pending', message: 'Transaction still IN PROCESS at operator.' });

    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // ── Raise complaint with femoney24 for a transaction ────────────────────────
  router.post("/api/recharge-transactions/:id/complain", async (req, res) => {
    try {
      const { message } = req.body || {};
      const txRow = await db.query("SELECT * FROM recharge_transactions WHERE id=?", [req.params.id]);
      if (!txRow.rows.length) return res.status(404).json({ success: false, message: "Transaction not found." });

      const prov = await db.query(
        "SELECT api_key FROM recharge_api_providers WHERE provider_key='femoney24' AND is_active=1 LIMIT 1"
      );
      if (!prov.rows.length || !prov.rows[0].api_key) {
        return res.status(400).json({ success: false, message: "femoney24 not configured or not active." });
      }

      const url = `http://femoney24.com/RechargeApi/complain.aspx` +
        `?Apitoken=${encodeURIComponent(prov.rows[0].api_key)}` +
        `&ClientId=${req.params.id}` +
        `&Message=${encodeURIComponent(message || '')}`;

      const raw = await fetch(url, { signal: AbortSignal.timeout(10000) }).then(r => r.text());
      let data;
      try { data = JSON.parse(raw); } catch (_) {
        return res.status(502).json({ success: false, message: "femoney24 returned non-JSON response." });
      }

      if (data.STATUS === 'SUCCESS') {
        return res.json({ success: true, message: data.MESSAGE || 'Complaint registered successfully.' });
      }
      return res.json({ success: false, message: data.MESSAGE || 'Complaint failed.' });
    } catch (err) { res.status(500).json({ success: false, message: err.message }); }
  });

  // ── Resolve stuck pending recharge transaction (mark failed + refund) ────────
  router.post("/api/recharge-transactions/:id/refund", async (req, res) => {
    try {
      const txRow = await db.query(
        "SELECT * FROM recharge_transactions WHERE id=? AND status='pending'",
        [req.params.id]
      );
      if (!txRow.rows.length) return res.status(404).json({ success: false, message: "Transaction not found or not pending." });
      const txn = txRow.rows[0];
      await db.query("UPDATE recharge_transactions SET status='failed' WHERE id=?", [txn.id]);
      await db.query("UPDATE users SET wallet_balance = wallet_balance + ? WHERE id=?", [txn.amount, txn.user_id]);
      await db.query(
        "INSERT INTO wallet_transactions (user_id, amount, type, reason, ref_id) VALUES (?,?,'credit','recharge_refund',?)",
        [txn.user_id, txn.amount, txn.id]
      );
      res.json({ success: true, message: `₹${txn.amount} refunded to user #${txn.user_id}` });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
  });

  // ── Reels Channel Proof ──────────────────────────────────────────────────
  router.get("/api/reels/channel-proof", async (req, res) => {
    try {
      const { rows } = await db.query(`SELECT * FROM reels_channel_proof ORDER BY sort_order, created_at DESC`);
      res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.post("/api/reels/channel-proof", async (req, res) => {
    try {
      const { channel_name, handle, videos } = req.body;
      if (!channel_name) return res.status(400).json({ error: 'channel_name required' });
      const videosJson = JSON.stringify(Array.isArray(videos) ? videos : []);
      await db.query(`INSERT INTO reels_channel_proof (channel_name, handle, videos) VALUES (?,?,?)`, [channel_name, handle || '', videosJson]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.delete("/api/reels/channel-proof/:id", async (req, res) => {
    try {
      await db.query(`DELETE FROM reels_channel_proof WHERE id = ?`, [parseInt(req.params.id)]);
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ── Reels Niche Config ───────────────────────────────────────────────────
  router.get("/api/reels/niche-config", async (req, res) => {
    try {
      const { rows } = await db.query(`SELECT * FROM reels_niche_config ORDER BY niche_label`);
      res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.post("/api/reels/niche-config", async (req, res) => {
    try {
      const { niche_label, video_url } = req.body;
      if (!niche_label) return res.status(400).json({ error: 'niche_label required' });
      await db.query(
        `INSERT INTO reels_niche_config (niche_label, video_url) VALUES (?,?)
         ON DUPLICATE KEY UPDATE video_url = VALUES(video_url)`,
        [niche_label, video_url || '']
      );
      res.json({ success: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // GET /admin/api/reels — list all user-generated reels
  router.get("/api/reels", async (req, res) => {
    try {
      const { rows } = await db.query(`
        SELECT r.id, r.topic, r.title, r.status, r.video_url, r.audio_url,
               r.created_at, u.name, u.email
        FROM reels r
        LEFT JOIN users u ON r.user_id = u.id
        ORDER BY r.created_at DESC
      `);
      res.json(rows);
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
  });

  // DELETE /admin/api/reels/:id — remove reel from DB and delete files from disk
  router.delete("/api/reels/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const { rows: reelRows } = await db.query(`SELECT id FROM reels WHERE id = ?`, [id]);
      const reel = reelRows[0];
      if (reel) {
        const videoPath = path.join(__dirname, '..', 'public', 'videos', `${id}.mp4`);
        const audioPath = path.join(__dirname, '..', 'public', 'audio', `${id}.mp3`);
        if (fs.existsSync(videoPath)) fs.unlinkSync(videoPath);
        if (fs.existsSync(audioPath)) fs.unlinkSync(audioPath);
        await db.query(`DELETE FROM reels WHERE id = ?`, [id]);
      }
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
  });

  // ── POST /admin/api/music/upload — store preset music in DB (survives redeploys) ──
  router.post('/api/music/upload', (req, res) => {
    const memUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 }, fileFilter: (_r, f, cb) => cb(null, /mp3|wav|mpeg|audio/.test(f.mimetype)) });
    memUpload.single('file')(req, res, async (err) => {
      if (err) return res.status(400).json({ error: err.message });
      if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
      const id        = ((req.body && req.body.musicId) || '').replace(/[^a-z0-9_-]/gi, '').toLowerCase();
      const isPreview = req.body && req.body.isPreview === '1';
      if (!id) return res.status(400).json({ error: 'musicId is required' });
      const col = isPreview ? 'preview_audio' : 'full_audio';
      try {
        await db.query(
          `INSERT INTO reels_music_presets (id, ${col}) VALUES (?, ?) ON DUPLICATE KEY UPDATE ${col} = VALUES(${col})`,
          [id, req.file.buffer]
        );
        res.json({ success: true, id, isPreview });
      } catch (e) { res.status(500).json({ error: e.message }); }
    });
  });

  // ── DELETE /admin/api/music/:id — remove a music preset from DB ──────────────
  router.delete('/api/music/:id', async (req, res) => {
    const id = req.params.id.replace(/[^a-z0-9_-]/gi, '').toLowerCase();
    if (!id) return res.status(400).json({ error: 'Invalid id' });
    try { await db.query(`DELETE FROM reels_music_presets WHERE id = ?`, [id]); res.json({ success: true }); }
    catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── GET /admin/api/music/list — list music presets stored in DB ───────────────
  router.get('/api/music/list', async (req, res) => {
    try {
      const { rows } = await db.query(
        `SELECT id, LENGTH(full_audio) AS full_size, LENGTH(preview_audio) AS preview_size FROM reels_music_presets ORDER BY created_at`
      );
      const files = rows.flatMap(r => {
        const out = [];
        if (r.full_size)    out.push({ name: `${r.id}.mp3`,         size: parseInt(r.full_size,10),    url: `/music/${r.id}.mp3` });
        if (r.preview_size) out.push({ name: `preview-${r.id}.mp3`, size: parseInt(r.preview_size,10), url: `/music/preview-${r.id}.mp3` });
        return out;
      });
      res.json({ files });
    } catch (e) { res.json({ files: [] }); }
  });

  // ── GET /admin/api/user-music/list — list user-uploaded custom music ──────────
  const userMusicDir = path.join(__dirname, '..', 'public', 'videos', 'temp', 'music');
  router.get('/api/user-music/list', (req, res) => {
    try {
      if (!fs.existsSync(userMusicDir)) return res.json({ files: [] });
      const files = fs.readdirSync(userMusicDir)
        .filter(f => /\.(mp3|wav)$/i.test(f))
        .map(f => {
          const stat = fs.statSync(path.join(userMusicDir, f));
          return { name: f, size: stat.size };
        });
      res.json({ files });
    } catch { res.json({ files: [] }); }
  });

  // ── DELETE /admin/api/user-music/:filename — delete user-uploaded music ───────
  router.delete('/api/user-music/:filename', (req, res) => {
    const safe = path.basename(req.params.filename);
    const full = path.join(userMusicDir, safe);
    if (!fs.existsSync(userMusicDir) || !full.startsWith(userMusicDir)) {
      return res.status(400).json({ error: 'Invalid path' });
    }
    try { fs.unlinkSync(full); res.json({ success: true }); }
    catch { res.status(404).json({ error: 'File not found' }); }
  });

  // ── POST /admin/api/art-gif/upload — admin uploads art style GIF ─────────────
  router.post('/api/art-gif/upload', (req, res) => {
    artGifUpload.single('file')(req, res, (err) => {
      if (err) return res.status(400).json({ error: err.message });
      if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
      res.json({ success: true, filename: req.file.filename });
    });
  });

  // ── DELETE /admin/api/art-gif/:artId — remove a GIF ─────────────────────────
  router.delete('/api/art-gif/:artId', (req, res) => {
    const safe = path.basename(req.params.artId) + '.gif';
    const full = path.join(artGifDir, safe);
    if (!full.startsWith(artGifDir)) return res.status(400).json({ error: 'Invalid' });
    try { fs.unlinkSync(full); res.json({ success: true }); }
    catch { res.status(404).json({ error: 'Not found' }); }
  });

  return router;
}

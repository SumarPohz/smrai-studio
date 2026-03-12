import { Router } from "express";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import { TEMPLATES } from "../config/templates-config.js";

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

export default function adminRouter(db) {
  const router = Router();

  // ── GET /admin — server-rendered dashboard with stats ──────────────────────
  router.get("/", async (req, res) => {
    try {
      const [users, resumes, downloads, revenue, aiUse, active24h] = await Promise.all([
        db.query("SELECT COUNT(*) FROM users"),
        db.query("SELECT COUNT(*) FROM resumes"),
        db.query("SELECT COUNT(*) FROM resume_events WHERE kind = 'download'"),
        db.query("SELECT COALESCE(SUM(amount),0) AS total FROM payments WHERE status = 'captured'"),
        db.query("SELECT COUNT(*) FROM activity_logs WHERE action_type LIKE 'ai_%'"),
        db.query(
          "SELECT COUNT(DISTINCT user_id) FROM activity_logs WHERE created_at > NOW() - INTERVAL '24 hours'"
        ),
      ]);

      res.render("admin/dashboard", {
        stats: {
          totalUsers:     +users.rows[0].count,
          activeToday:    +active24h.rows[0].count,
          totalResumes:   +resumes.rows[0].count,
          totalDownloads: +downloads.rows[0].count,
          totalRevenue:   Math.round(+revenue.rows[0].total / 100), // paise → rupees
          aiRequests:     +aiUse.rows[0].count,
        },
      });
    } catch (err) {
      res.status(500).send("Dashboard error");
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
          u.id, u.name, u.email, u.role, u.is_active,
          up.full_name, up.phone, up.location, up.profile_image_url, up.updated_at AS created_at,
          (SELECT COUNT(*)::int FROM resumes        WHERE user_id = u.id)                           AS resume_count,
          (SELECT COUNT(*)::int FROM resume_events  WHERE user_id = u.id AND kind = 'download')     AS download_count,
          (SELECT COALESCE(SUM(p.amount),0) FROM payments p WHERE p.user_id = u.id AND p.status = 'captured') AS total_paid,
          (SELECT MAX(al.created_at) FROM activity_logs al WHERE al.user_id = u.id)                AS last_active
        FROM users u
        LEFT JOIN user_profiles up ON up.user_id = u.id
        ${q ? "WHERE u.name ILIKE $3 OR u.email ILIKE $3" : ""}
        ORDER BY u.id DESC
        LIMIT $1 OFFSET $2
      `;

      const countSql = `SELECT COUNT(*) FROM users u ${q ? "WHERE u.name ILIKE $1 OR u.email ILIKE $1" : ""}`;

      const [rows, countRes] = await Promise.all([
        db.query(sql,      q ? [limit, offset, q] : [limit, offset]),
        db.query(countSql, q ? [q] : []),
      ]);

      res.json({
        success: true,
        users:   rows.rows,
        total:   +countRes.rows[0].count,
        page,
        limit,
      });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/api/user/:id — full user detail for modal ──────────────────
  router.get("/api/user/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (!id) return res.status(400).json({ success: false });

      const [userRes, profileRes, countsRes] = await Promise.all([
        db.query(
          "SELECT id, name, email, role, is_active FROM users WHERE id = $1",
          [id]
        ),
        db.query("SELECT * FROM user_profiles WHERE user_id = $1", [id]),
        db.query(
          `SELECT
            (SELECT COUNT(*)::int FROM resumes        WHERE user_id = $1)                           AS resumes,
            (SELECT COUNT(*)::int FROM resume_events  WHERE user_id = $1 AND kind = 'download')     AS downloads,
            (SELECT COUNT(*)::int FROM activity_logs  WHERE user_id = $1 AND action_type LIKE 'ai_%') AS ai_uses,
            (SELECT COALESCE(SUM(amount),0) FROM payments WHERE user_id = $1 AND status = 'captured') AS total_paid,
            (SELECT MAX(created_at) FROM activity_logs WHERE user_id = $1)                          AS last_active`,
          [id]
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

      if (!id || !["admin", "user"].includes(role)) {
        return res.status(400).json({ success: false, message: "Invalid request" });
      }
      if (id === req.user.id && role === "user") {
        return res.status(403).json({ success: false, message: "Cannot demote yourself" });
      }

      await db.query("UPDATE users SET role = $1 WHERE id = $2", [role, id]);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── PATCH /admin/api/user/:id/toggle-active — activate / deactivate ──────
  router.patch("/api/user/:id/toggle-active", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      if (!id) return res.status(400).json({ success: false });
      if (id === req.user.id) {
        return res.status(403).json({ success: false, message: "Cannot deactivate yourself" });
      }
      const result = await db.query(
        "UPDATE users SET is_active = NOT is_active WHERE id = $1 RETURNING is_active",
        [id]
      );
      if (!result.rows.length) return res.status(404).json({ success: false });
      res.json({ success: true, is_active: result.rows[0].is_active });
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
      await db.query("DELETE FROM users WHERE id = $1", [id]);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── DELETE /admin/api/activity — clear logs by period ────────────────────
  router.delete("/api/activity", async (req, res) => {
    const { period } = req.query;
    try {
      let result;
      if (period === "recent") {
        result = await db.query(
          `DELETE FROM activity_logs WHERE created_at >= NOW() - INTERVAL '1 hour'`
        );
      } else if (period === "today") {
        result = await db.query(
          `DELETE FROM activity_logs WHERE created_at::date = CURRENT_DATE`
        );
      } else if (period === "yesterday") {
        result = await db.query(
          `DELETE FROM activity_logs WHERE created_at::date = CURRENT_DATE - INTERVAL '1 day'`
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
        LIMIT $1`,
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
             COUNT(*)::int                         AS activity_count,
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
             COUNT(*)::int                              AS total_visits,
             COUNT(DISTINCT metadata->>'sid')::int      AS unique_sessions,
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
          `SELECT route, COUNT(*)::int AS visits, MAX(created_at) AS last_visit
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
         WHERE user_id = $1
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
          `SELECT route, COUNT(*)::int AS hits
           FROM activity_logs WHERE action_type = 'visit' AND route IS NOT NULL
           GROUP BY route ORDER BY hits DESC LIMIT 8`
        ),
        db.query(
          `SELECT r.template, COUNT(*)::int AS downloads
           FROM resume_events re
           JOIN resumes r ON r.id = re.resume_id
           WHERE re.kind = 'download'
           GROUP BY r.template ORDER BY downloads DESC`
        ),
        db.query(
          `SELECT DATE(created_at) AS day, ROUND(SUM(amount)/100.0, 2) AS revenue
           FROM payments WHERE status = 'captured' AND created_at > NOW() - INTERVAL '30 days'
           GROUP BY day ORDER BY day`
        ),
        db.query(
          `SELECT DATE(created_at) AS day, COUNT(*)::int AS count
           FROM activity_logs WHERE action_type LIKE 'ai_%' AND created_at > NOW() - INTERVAL '30 days'
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

      const where  = status ? "WHERE status = $3" : "";
      const params = status ? [limit, offset, status] : [limit, offset];

      const [rows, countRes] = await Promise.all([
        db.query(
          `SELECT id, name, email, service_type, details, status, created_at
           FROM service_requests
           ${where}
           ORDER BY created_at DESC
           LIMIT $1 OFFSET $2`,
          params
        ),
        db.query(
          `SELECT COUNT(*)::int AS count FROM service_requests ${status ? "WHERE status = $1" : ""}`,
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
      await db.query("UPDATE service_requests SET status = $1 WHERE id = $2", [status, id]);
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
      await db.query("DELETE FROM service_requests WHERE id = $1", [id]);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── GET /admin/api/settings — return all key-value settings ──────────────
  router.get("/api/settings", async (req, res) => {
    try {
      const result = await db.query("SELECT key, value FROM admin_settings ORDER BY key");
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
      const PRICE_KEYS   = ["price_fresher", "price_experienced", "price_developer", "price_ats-friendly"];
      const GENERAL_KEYS = ["adsense_publisher_id", "facebook_pixel_id", "homepage_ad_slot", "footer_ad_slot", "ads_enabled"];
      const ALLOWED_KEYS = [...PRICE_KEYS, ...GENERAL_KEYS];
      const updates = req.body || {};
      const entries = Object.entries(updates).filter(([k]) => ALLOWED_KEYS.includes(k));

      if (!entries.length) return res.status(400).json({ success: false, message: "No valid keys" });

      for (const [key, value] of entries) {
        if (PRICE_KEYS.includes(key)) {
          const num = parseInt(value, 10);
          if (isNaN(num) || num < 0) return res.status(400).json({ success: false, message: `Invalid value for ${key}` });
          await db.query(
            `INSERT INTO admin_settings (key, value, updated_at) VALUES ($1, $2, NOW())
             ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
            [key, String(num)]
          );
        } else {
          const strVal = String(value ?? '').trim();
          await db.query(
            `INSERT INTO admin_settings (key, value, updated_at) VALUES ($1, $2, NOW())
             ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
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
          (SELECT COUNT(*)::int FROM admin_template_sections s WHERE s.template_id = t.id AND s.is_enabled = true) AS enabled_sections,
          (SELECT COUNT(*)::int FROM resumes r WHERE r.template = t.slug) AS usage_count
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
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
        [
          tempSlug, title, description || null,
          category || "experienced", badge || "New",
          layout_type || "two-column-left",
          JSON.stringify(color_scheme || { primary: "#1e3a5f", secondary: "#f3f4f6", accent: "#3b82f6", text: "#1f2937" }),
          is_paid !== false, price_inr || 49, req.user.id,
        ]
      );
      const newId = insert.rows[0].id;
      // Update slug to include real id
      const finalSlug = `adm-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-").substring(0, 40)}-${newId}`;
      await db.query("UPDATE admin_templates SET slug=$1, updated_at=NOW() WHERE id=$2", [finalSlug, newId]);

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
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [newId, s.key, !s.disabled, s.order, s.placement, s.display, null]
        );
      }

      const tpl = await db.query("SELECT * FROM admin_templates WHERE id=$1", [newId]);
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
          title=$1, description=$2, category=$3, badge=$4, layout_type=$5,
          color_scheme=$6, is_paid=$7, price_inr=$8, sort_order=$9,
          design_settings=$10, updated_at=NOW()
         WHERE id=$11`,
        [
          title, description || null, category || "experienced", badge || "New",
          layout_type || "two-column-left",
          JSON.stringify(color_scheme || { primary: "#1e3a5f", secondary: "#f3f4f6", accent: "#3b82f6", text: "#1f2937" }),
          is_paid !== false, price_inr || 49, sort_order || 0,
          JSON.stringify(design_settings || DEFAULT_DESIGN),
          id,
        ]
      );
      const tpl = await db.query("SELECT * FROM admin_templates WHERE id=$1", [id]);
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
      await db.query("DELETE FROM admin_templates WHERE id=$1", [id]);
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
      const current = await db.query("SELECT is_published FROM admin_templates WHERE id=$1", [id]);
      if (!current.rows[0]) return res.status(404).json({ success: false });
      const newState = !current.rows[0].is_published;
      await db.query("UPDATE admin_templates SET is_published=$1, updated_at=NOW() WHERE id=$2", [newState, id]);
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
        "UPDATE admin_templates SET thumbnail_url=$1, updated_at=NOW() WHERE id=$2",
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
        "UPDATE admin_templates SET thumbnail_url=$1, updated_at=NOW() WHERE id=$2",
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
        "UPDATE admin_templates SET background_image_url=$1, updated_at=NOW() WHERE id=$2",
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
      await db.query("UPDATE admin_templates SET background_image_url=NULL, updated_at=NOW() WHERE id=$1", [id]);
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
        "SELECT section_key, is_enabled, sort_order, placement, display_type, label_override FROM admin_template_sections WHERE template_id=$1 ORDER BY sort_order",
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
      await db.query("DELETE FROM admin_template_sections WHERE template_id=$1", [id]);
      for (const s of sections) {
        await db.query(
          `INSERT INTO admin_template_sections
             (template_id, section_key, is_enabled, sort_order, placement, display_type, label_override)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [id, s.section_key, s.is_enabled !== false, s.sort_order || 0,
           s.placement || 'auto', s.display_type || 'bullets', s.label_override || null]
        );
      }
      await db.query("UPDATE admin_templates SET updated_at=NOW() WHERE id=$1", [id]);
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
      const rows = (await db.query(`SELECT key, value FROM admin_settings WHERE key = ANY($1)`, [keys])).rows;
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
        `INSERT INTO admin_settings (key, value, updated_at) VALUES ($1,$2,NOW())
         ON CONFLICT (key) DO UPDATE SET value=$2, updated_at=NOW()`,
        [key, value]
      );
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false });
    }
  });

  // ── POST /admin/api/homepage/upload-image — upload avatar/service image ──────
  router.post("/api/homepage/upload-image", tplUpload.single("image"), (req, res) => {
    if (!req.file) return res.status(400).json({ success: false, error: "No file uploaded" });
    res.json({ success: true, imageUrl: `/images/templates/uploads/${req.file.filename}` });
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
        VALUES ($1,$2,$3,$4,$5,NOW())
        ON CONFLICT (template_id) DO UPDATE SET
          title        = COALESCE(EXCLUDED.title,        template_overrides.title),
          description  = COALESCE(EXCLUDED.description,  template_overrides.description),
          badge        = COALESCE(EXCLUDED.badge,         template_overrides.badge),
          is_available = COALESCE(EXCLUDED.is_available,  template_overrides.is_available),
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
        VALUES ($1,$2,NOW())
        ON CONFLICT (template_id) DO UPDATE SET
          preview_image_url = EXCLUDED.preview_image_url,
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
        VALUES ($1,$2,NOW())
        ON CONFLICT (template_id) DO UPDATE SET
          background_image_url = EXCLUDED.background_image_url,
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
        INSERT INTO template_overrides (template_id, background_image_url, updated_at) VALUES ($1,NULL,NOW())
        ON CONFLICT (template_id) DO UPDATE SET background_image_url=NULL, updated_at=NOW()
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
      const tplRow = await db.query("SELECT * FROM admin_templates WHERE slug=$1", [slug]);
      const adminTemplateConfig = tplRow.rows[0] || null;
      if (!adminTemplateConfig) return res.status(404).send("Template not found");

      const secRes = await db.query(
        "SELECT section_key, is_enabled, sort_order, placement, display_type, label_override FROM admin_template_sections WHERE template_id=$1 ORDER BY sort_order",
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
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
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
      res.json({ success: true, coupon: result.rows[0] });
    } catch (err) {
      if (err.code === "23505") return res.status(400).json({ success: false, error: "A coupon with that code already exists." });
      res.status(500).json({ success: false, error: "Server error." });
    }
  });

  router.put("/api/coupons/:id/toggle", async (req, res) => {
    try {
      const result = await db.query(
        "UPDATE coupons SET is_active = NOT is_active WHERE id=$1 RETURNING *",
        [parseInt(req.params.id, 10)]
      );
      res.json({ success: true, coupon: result.rows[0] });
    } catch { res.status(500).json({ success: false }); }
  });

  router.delete("/api/coupons/:id", async (req, res) => {
    try {
      await db.query("DELETE FROM coupons WHERE id=$1", [parseInt(req.params.id, 10)]);
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
      const rows = await db.query(
        "SELECT key, value FROM admin_settings WHERE key = ANY($1)",
        [ENV_WHITELIST.map(k => `env_${k.toLowerCase()}`)]
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
          `INSERT INTO admin_settings (key, value, updated_at) VALUES ($1,$2,NOW())
           ON CONFLICT (key) DO UPDATE SET value=$2, updated_at=NOW()`,
          [dbKey, strVal]
        );
        if (strVal) process.env[key] = strVal;
      }
      res.json({ success: true });
    } catch { res.status(500).json({ success: false }); }
  });

  router.get("/api/ads/settings", async (req, res) => {
    try {
      const r = await db.query("SELECT value FROM admin_settings WHERE key='ads_enabled'");
      res.json({ success: true, adsEnabled: (r.rows[0]?.value ?? 'true') === 'true' });
    } catch { res.status(500).json({ success: false }); }
  });

  router.put("/api/ads/settings", async (req, res) => {
    try {
      const enabled = req.body.enabled !== false;
      await db.query("UPDATE admin_settings SET value=$1 WHERE key='ads_enabled'", [enabled ? 'true' : 'false']);
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
        "INSERT INTO ads (slot, title, image_url, link_url) VALUES ($1,$2,$3,$4) RETURNING *",
        [slot, title || null, image_url, link_url]
      );
      res.json({ success: true, ad: result.rows[0] });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  router.put("/api/ads/:id/toggle", async (req, res) => {
    try {
      const result = await db.query(
        "UPDATE ads SET is_active = NOT is_active WHERE id=$1 RETURNING *",
        [parseInt(req.params.id, 10)]
      );
      res.json({ success: true, ad: result.rows[0] });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  router.delete("/api/ads/:id", async (req, res) => {
    try {
      const row = await db.query("DELETE FROM ads WHERE id=$1 RETURNING image_url", [parseInt(req.params.id, 10)]);
      if (row.rows[0]?.image_url) {
        const filePath = path.join(__dirname, "..", "public", row.rows[0].image_url);
        fs.unlink(filePath, () => {});
      }
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false }); }
  });

  return router;
}

import { Router } from "express";

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
      console.error("Admin dashboard error:", err);
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
      console.error("Admin users error:", err);
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
      console.error("Admin user detail error:", err);
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
      console.error("Admin role update error:", err);
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
      console.error("Toggle active error:", err);
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
      console.error("Delete user error:", err);
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
      console.error("Activity delete error:", err);
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
      console.error("Admin activity error:", err);
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
      console.error("Activity grouped error:", err);
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
      console.error("Guest activity error:", err);
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
      console.error("User activity error:", err);
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
      console.error("Stat detail error:", err);
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
      console.error("Admin charts error:", err);
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
      console.error("Service requests error:", err);
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
      console.error("Service request status error:", err);
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
      console.error("Service request delete error:", err);
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
      console.error("Admin settings GET error:", err);
      res.status(500).json({ success: false });
    }
  });

  // ── PATCH /admin/api/settings — update one or more settings ──────────────
  router.patch("/api/settings", async (req, res) => {
    try {
      const ALLOWED_KEYS = ["price_fresher", "price_experienced", "price_developer", "price_ats-friendly"];
      const updates = req.body || {};
      const entries = Object.entries(updates).filter(([k]) => ALLOWED_KEYS.includes(k));

      if (!entries.length) return res.status(400).json({ success: false, message: "No valid keys" });

      for (const [key, value] of entries) {
        const num = parseInt(value, 10);
        if (isNaN(num) || num < 0) return res.status(400).json({ success: false, message: `Invalid value for ${key}` });
        await db.query(
          `INSERT INTO admin_settings (key, value, updated_at) VALUES ($1, $2, NOW())
           ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
          [key, String(num)]
        );
      }

      res.json({ success: true });
    } catch (err) {
      console.error("Admin settings PATCH error:", err);
      res.status(500).json({ success: false });
    }
  });

  return router;
}

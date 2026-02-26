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
          u.id, u.name, u.email, u.role, u.created_at,
          up.full_name, up.phone, up.location, up.profile_image_url,
          (SELECT COUNT(*)::int FROM resumes        WHERE user_id = u.id)                           AS resume_count,
          (SELECT COUNT(*)::int FROM resume_events  WHERE user_id = u.id AND kind = 'download')     AS download_count,
          (SELECT COALESCE(SUM(p.amount),0) FROM payments p WHERE p.user_id = u.id AND p.status = 'captured') AS total_paid,
          (SELECT MAX(al.created_at) FROM activity_logs al WHERE al.user_id = u.id)                AS last_active
        FROM users u
        LEFT JOIN user_profiles up ON up.user_id = u.id
        ${q ? "WHERE u.name ILIKE $3 OR u.email ILIKE $3" : ""}
        ORDER BY u.created_at DESC
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
          "SELECT id, name, email, role, created_at FROM users WHERE id = $1",
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
          ...userRes.rows[0],
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

  // ── GET /admin/api/activity — latest activity feed ────────────────────────
  router.get("/api/activity", async (req, res) => {
    try {
      const limit = Math.min(100, parseInt(req.query.limit) || 50);
      const rows = await db.query(
        `SELECT
          al.id, al.action_type, al.route, al.metadata, al.ip_address, al.created_at,
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

  return router;
}

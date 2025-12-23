const mysql = require("mysql2/promise");

let pool = null;

// Initialize pool lazily (only once)
function initPool() {
  if (pool) return pool;

  if (
    !process.env.MYSQL_HOST ||
    !process.env.MYSQL_USER ||
    !process.env.MYSQL_DATABASE
  ) {
    console.warn("⚠️ MySQL env vars missing — DB disabled");
    return null;
  }

  pool = mysql.createPool({
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE,
    port: process.env.MYSQL_PORT
      ? Number(process.env.MYSQL_PORT)
      : 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });

  console.log("✅ MySQL pool initialized");
  return pool;
}

const db = {
  query: async (sql, params = []) => {
    const pool = initPool();

    if (!pool) {
      throw new Error("Database not initialized (env vars missing)");
    }

    const [result] = await pool.query(sql, params);

    if (Array.isArray(result)) {
      return { rows: result };
    }

    return {
      rows: [],
      insertId: result.insertId || null,
      affectedRows: result.affectedRows || 0,
    };
  },
};

module.exports = db;

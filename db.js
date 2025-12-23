import mysql from "mysql2/promise";

console.log("DB CONFIG CHECK (raw):", {
  MYSQL_HOST: process.env.MYSQL_HOST,
  MYSQL_USER: process.env.MYSQL_USER,
  MYSQL_PASSWORD: process.env.MYSQL_PASSWORD ? "***set***" : undefined,
  MYSQL_DATABASE: process.env.MYSQL_DATABASE,
  MYSQL_PORT: process.env.MYSQL_PORT,
  NODE_ENV: process.env.NODE_ENV,
});

const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  port: process.env.MYSQL_PORT ? Number(process.env.MYSQL_PORT) : 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const db = {
  query: async (sql, params = []) => {
    try {
      const [result] = await pool.query(sql, params);

      if (Array.isArray(result)) {
        return { rows: result };
      }

      return {
        rows: [],
        insertId: result.insertId || null,
        affectedRows: result.affectedRows || 0,
      };
    } catch (err) {
      console.error("❌ DB QUERY ERROR");
      console.error("SQL:", sql);
      console.error("PARAMS:", params);
      console.error("ERROR:", err.message);
      throw err;
    }
  },
};

// 🔍 Test DB connection once at startup
(async () => {
  try {
    const conn = await pool.getConnection();
    console.log("✅ MySQL connected successfully");
    conn.release();
  } catch (err) {
    console.error("❌ MySQL connection failed:", err.message);
  }
})();

export default db;

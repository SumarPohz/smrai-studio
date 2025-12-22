import mysql from "mysql2/promise";
import env from "dotenv";

env.config();

console.log("DB CONFIG CHECK:", {
host: process.env.MYSQL_HOST,
user: process.env.MYSQL_USER,
database: process.env.MYSQL_DATABASE,
port: process.env.MYSQL_PORT,
});


const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const db = {
  query: async (sql, params = []) => {
    const [result] = await pool.query(sql, params);

    // SELECT
    if (Array.isArray(result)) {
      return { rows: result };
    }

    // INSERT / UPDATE / DELETEE
    return {
      rows: [],
      insertId: result.insertId || null,
      affectedRows: result.affectedRows || 0,
    };
  },
};

export default db;

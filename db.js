import mysql from "mysql2/promise";
require('dotenv').config();

console.log("DB CONFIG CHECK (raw):", {
 MYSQL_HOST: process.env.MYSQL_HOST,
 MYSQL_USER: process.env.MYSQL_USER,
 MYSQL_PASSWORD: process.env.MYSQL_PASSWORD ? "***set***" : undefined,
 MYSQL_DATABASE: process.env.MYSQL_DATABASE,
 MYSQL_PORT: process.env.MYSQL_PORT,
 NODE_ENV: process.env.NODE_ENV,
});

const pool = mysql.createPool({
 host: "YOUR_DB_HOST", // from hPanel → Databases → MySQL Databases → Host
 user: "YOUR_DB_USER", // your MySQL username
 password: "YOUR_DB_PASSWORD",
 database: "YOUR_DB_NAME", // your MySQL database name
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

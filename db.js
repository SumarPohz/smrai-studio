const mysql = require("mysql2/promise");

let pool;

function initPool() {
 if (pool) return pool;

 pool = mysql.createPool({
 host: process.env.MYSQL_HOST,
 user: process.env.MYSQL_USER,
 password: process.env.MYSQL_PASSWORD,
 database: process.env.MYSQL_DATABASE,
 port: Number(process.env.MYSQL_PORT) || 3306,

 waitForConnections: true,
 connectionLimit: 5,
 queueLimit: 0,
 });
 return pool;
}

module.exports = {
 async query(sql, params = []) {
 const db = initPool();
 const [rows] = await db.execute(sql, params);
 return { rows };
 },
};
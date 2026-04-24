const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  host:     process.env.DB_HOST,
  port:     parseInt(process.env.DB_PORT) || 5432,
  database: process.env.DB_NAME,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

pool.on('error', (err) => {
  console.error('❌ PostgreSQL pool error:', err.message);
});

// Test connection au démarrage
pool.connect()
  .then(client => {
    console.log('✅ PostgreSQL connecté');
    client.release();
  })
  .catch(err => {
    console.error('❌ Connexion PostgreSQL échouée:', err.message);
    process.exit(1);
  });

module.exports = pool;

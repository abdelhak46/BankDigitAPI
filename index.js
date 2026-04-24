require('dotenv').config();
const express    = require('express');
const helmet     = require('helmet');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');

// ── Routes
const authRoutes          = require('./auth.routes');
const accountRoutes       = require('./account.routes');
const transfersRoutes     = require('./transfers.routes');
const cardRoutes          = require('./card.routes');
const usersRoutes         = require('./users.routes');
const notificationsRoutes = require('./notifications.routes');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────────────────────
// Sécurité & middlewares globaux
// ─────────────────────────────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '10kb' }));

// Rate limiting — anti brute-force
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Trop de requêtes, veuillez réessayer plus tard.' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Trop de tentatives de connexion.' },
});

app.use('/api/', globalLimiter);
app.use('/api/v1/auth/login',    authLimiter);
app.use('/api/v1/auth/register', authLimiter);

// ─────────────────────────────────────────────────────────────
// Routes API
// ─────────────────────────────────────────────────────────────
app.use('/api/v1/auth',          authRoutes);
app.use('/api/v1/account',       accountRoutes);
app.use('/api/v1',               transfersRoutes);   // contient /transfers_interen, /transfers_externe, /transfers
app.use('/api/v1/card',          cardRoutes);
app.use('/api/v1/users',         usersRoutes);
app.use('/api/v1/notifications', notificationsRoutes);

// ─────────────────────────────────────────────────────────────
// Health check
// ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0', env: process.env.NODE_ENV });
});

// ─────────────────────────────────────────────────────────────
// 404 handler
// ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} introuvable` });
});

// ─────────────────────────────────────────────────────────────
// Global error handler
// ─────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('💥 Unhandled error:', err);
  res.status(500).json({ error: 'Erreur interne du serveur' });
});

// ─────────────────────────────────────────────────────────────
// Démarrage
// ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 BankDigit API démarrée sur http://localhost:${PORT}`);
  console.log(`📋 Environnement : ${process.env.NODE_ENV}`);
});

module.exports = app;

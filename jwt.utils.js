const jwt = require('jsonwebtoken');
require('dotenv').config();

// ── Génère un access token (15min)
const signAccess = (payload) =>
  jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.JWT_ACCESS_EXPIRES || '15m',
  });

// ── Génère un refresh token (7j)
const signRefresh = (payload) =>
  jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES || '7d',
  });

// ── Génère un token temporaire après login (en attente OTP)
const signTemp = (payload) =>
  jwt.sign(payload, process.env.JWT_TEMP_SECRET, {
    expiresIn: process.env.JWT_TEMP_EXPIRES || '10m',
  });

// ── Vérifie un access token
const verifyAccess = (token) =>
  jwt.verify(token, process.env.JWT_ACCESS_SECRET);

// ── Vérifie un refresh token
const verifyRefresh = (token) =>
  jwt.verify(token, process.env.JWT_REFRESH_SECRET);

// ── Vérifie un token temporaire (OTP step)
const verifyTemp = (token) =>
  jwt.verify(token, process.env.JWT_TEMP_SECRET);

module.exports = { signAccess, signRefresh, signTemp, verifyAccess, verifyRefresh, verifyTemp };

const crypto = require('crypto');
const pool   = require('./db');

// ── Génère un code OTP à 6 chiffres
const generateOtp = () =>
  String(crypto.randomInt(100000, 999999));

/**
 * Crée et stocke un OTP en base
 * @param {string} userId
 * @param {string} purpose - 'login' | 'transfer' | 'card_action' | 'email_verify'
 * @returns {string} code OTP en clair (à envoyer par email)
 */
const createOtp = async (userId, purpose) => {
  const code      = generateOtp();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

  // Invalide les anciens OTPs du même type pour cet user
  await pool.query(
    `UPDATE otp_codes SET used = TRUE
     WHERE user_id = $1 AND purpose = $2 AND used = FALSE`,
    [userId, purpose]
  );

  await pool.query(
    `INSERT INTO otp_codes (user_id, code, purpose, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [userId, code, purpose, expiresAt]
  );

  return code;
};

/**
 * Vérifie un OTP
 * @returns {{ valid: boolean, reason?: string }}
 */
const verifyOtp = async (userId, code, purpose) => {
  const { rows } = await pool.query(
    `SELECT id, expires_at, used
     FROM otp_codes
     WHERE user_id = $1 AND code = $2 AND purpose = $3
     ORDER BY created_at DESC
     LIMIT 1`,
    [userId, code, purpose]
  );

  if (!rows.length)      return { valid: false, reason: 'Code incorrect' };
  const otp = rows[0];
  if (otp.used)          return { valid: false, reason: 'Code déjà utilisé' };
  if (new Date() > new Date(otp.expires_at))
                         return { valid: false, reason: 'Code expiré' };

  // Marquer comme utilisé
  await pool.query(`UPDATE otp_codes SET used = TRUE WHERE id = $1`, [otp.id]);

  return { valid: true };
};

module.exports = { createOtp, verifyOtp };

const express  = require('express');
const bcrypt   = require('bcrypt');
const crypto   = require('crypto');
const pool     = require('./db');
const { signAccess, signRefresh, signTemp, verifyRefresh } = require('./jwt.utils');
const { createOtp, verifyOtp } = require('./otp.utils');
const { sendOtpEmail, sendVerifyEmail } = require('./mailer');
const { requireTempToken } = require('./auth.middleware');

const router = express.Router();

// ─────────────────────────────────────────────────────────────
// Helpers carte
// ─────────────────────────────────────────────────────────────

// Numéro Visa à 16 chiffres (préfixe 4)
const generateCardNumber = () =>
  '4' + Array.from({ length: 15 }, () => Math.floor(Math.random() * 10)).join('');

// CVV à 3 chiffres
const generateCvv = () =>
  String(crypto.randomInt(100, 999));

// Date d'expiration : +4 ans
const generateExpiryDate = () => {
  const d = new Date();
  d.setFullYear(d.getFullYear() + 4);
  return d.toISOString().split('T')[0];
};

// ─────────────────────────────────────────────────────────────
// POST /api/v1/auth/register
// ─────────────────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const { nom, prenom, email, mot_de_passe, telephone, date_naissance, adresse } = req.body;

  if (!nom || !prenom || !email || !mot_de_passe)
    return res.status(400).json({ error: 'Champs obligatoires manquants' });

  if (mot_de_passe.length < 8)
    return res.status(400).json({ error: 'Mot de passe trop court (min 8 caractères)' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Vérifier email unique
    const { rows: existing } = await client.query(
      `SELECT user_id FROM "user" WHERE email = $1`, [email]
    );
    if (existing.length)
      return res.status(409).json({ error: 'Email déjà utilisé' });

    // Hasher le mot de passe
    const hash = await bcrypt.hash(mot_de_passe, 12);

    // Créer l'utilisateur
    const { rows: [user] } = await client.query(
      `INSERT INTO "user" (nom, prenom, email, mot_de_passe, telephone, date_naissance, adresse)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING user_id, email`,
      [nom, prenom, email, hash, telephone || null, date_naissance || null, adresse || null]
    );

    // ── Créer le compte bancaire
    const rib = 'DZ' + Date.now() + Math.floor(Math.random() * 10000);
    const { rows: [account] } = await client.query(
      `INSERT INTO account (user_id, rib, solde, devise, type_compte)
       VALUES ($1, $2, 0, 'DZD', 'courant')
       RETURNING account_id`,
      [user.user_id, rib]
    );

    // ── Créer la carte VIRTUELLE automatiquement
    //    statut          : inactive  → activable via POST /card/activate + OTP
    //    paiement_internet : TRUE    → faite pour les achats en ligne
    //    contactless     : FALSE     → pas de NFC sur une carte virtuelle
    //    plafond_retrait : 0         → pas de retrait DAB
    //    plafond_paiement: 50 000 DZD
    const cvvPlain = generateCvv();
    const cvvHash  = await bcrypt.hash(cvvPlain, 10);
    const titulaire = `${prenom.toUpperCase()} ${nom.toUpperCase()}`;

    await client.query(
      `INSERT INTO card
         (account_id, titulaire, numero_carte, cvv_hash, date_expiration,
          reseau, type_carte, statut,
          plafond_paiement, plafond_retrait,
          contactless, paiement_internet)
       VALUES ($1,$2,$3,$4,$5,'Visa','virtuelle','inactive',50000,0,FALSE,TRUE)`,
      [account.account_id, titulaire, generateCardNumber(), cvvHash, generateExpiryDate()]
    );

    // ── Token de vérification email
    const token     = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await client.query(
      `INSERT INTO email_verifications (user_id, token, expires_at) VALUES ($1,$2,$3)`,
      [user.user_id, token, expiresAt]
    );

    await client.query('COMMIT');

    const verifyUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
    await sendVerifyEmail(email, verifyUrl).catch(console.error);

    res.status(201).json({
      message: 'Compte créé. Vérifiez votre email pour activer votre compte.',
      user_id: user.user_id,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────
// POST /api/v1/auth/verify-email
// ─────────────────────────────────────────────────────────────
router.post('/verify-email', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token manquant' });

  const { rows } = await pool.query(
    `SELECT ev.user_id, ev.expires_at, ev.used
     FROM email_verifications ev WHERE ev.token = $1`, [token]
  );

  if (!rows.length)                              return res.status(404).json({ error: 'Token invalide' });
  if (rows[0].used)                              return res.status(400).json({ error: 'Token déjà utilisé' });
  if (new Date() > new Date(rows[0].expires_at)) return res.status(400).json({ error: 'Token expiré' });

  await pool.query(`UPDATE email_verifications SET used = TRUE WHERE token = $1`, [token]);
  await pool.query(`UPDATE "user" SET kyc_valide = TRUE, updated_at = NOW() WHERE user_id = $1`, [rows[0].user_id]);

  res.json({ message: 'Email vérifié avec succès.' });
});

// ─────────────────────────────────────────────────────────────
// POST /api/v1/auth/login
// ─────────────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { email, mot_de_passe } = req.body;
  if (!email || !mot_de_passe)
    return res.status(400).json({ error: 'Email et mot de passe requis' });

  const { rows } = await pool.query(
    `SELECT user_id, email, mot_de_passe, statut FROM "user" WHERE email = $1`, [email]
  );
  if (!rows.length)              return res.status(401).json({ error: 'Identifiants incorrects' });
  const user = rows[0];
  if (user.statut === 'bloqué') return res.status(403).json({ error: 'Compte bloqué' });
  if (user.statut === 'fermé')  return res.status(403).json({ error: 'Compte fermé' });

  const match = await bcrypt.compare(mot_de_passe, user.mot_de_passe);
  if (!match) return res.status(401).json({ error: 'Identifiants incorrects' });

  const code = await createOtp(user.user_id, 'login');
  await sendOtpEmail(user.email, code, 'login').catch(console.error);

  const tempToken = signTemp({ user_id: user.user_id, email: user.email, step: '2fa' });
  res.json({ message: 'Code OTP envoyé à votre adresse email.', temp_token: tempToken });
});

// ─────────────────────────────────────────────────────────────
// POST /api/v1/auth/2fa/verify
// ─────────────────────────────────────────────────────────────
router.post('/2fa/verify', requireTempToken, async (req, res) => {
  const { code } = req.body;
  const { user_id, email } = req.tempUser;
  if (!code) return res.status(400).json({ error: 'Code OTP requis' });

  const result = await verifyOtp(user_id, code, 'login');
  if (!result.valid) return res.status(401).json({ error: result.reason });

  const accessToken  = signAccess({ user_id, email });
  const refreshToken = signRefresh({ user_id, email });

  const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  await pool.query(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1,$2,$3)`,
    [user_id, tokenHash, expiresAt]
  );

  res.json({ access_token: accessToken, refresh_token: refreshToken });
});

// ─────────────────────────────────────────────────────────────
// POST /api/v1/auth/refresh
// ─────────────────────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ error: 'Refresh token requis' });

  let payload;
  try { payload = verifyRefresh(refresh_token); }
  catch { return res.status(401).json({ error: 'Refresh token invalide ou expiré' }); }

  const hash = crypto.createHash('sha256').update(refresh_token).digest('hex');
  const { rows } = await pool.query(
    `SELECT id FROM refresh_tokens
     WHERE user_id = $1 AND token_hash = $2 AND expires_at > NOW()`,
    [payload.user_id, hash]
  );
  if (!rows.length) return res.status(401).json({ error: 'Session révoquée' });

  const newAccess  = signAccess({ user_id: payload.user_id, email: payload.email });
  const newRefresh = signRefresh({ user_id: payload.user_id, email: payload.email });
  const newHash    = crypto.createHash('sha256').update(newRefresh).digest('hex');
  const expiresAt  = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await pool.query(`DELETE FROM refresh_tokens WHERE id = $1`, [rows[0].id]);
  await pool.query(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1,$2,$3)`,
    [payload.user_id, newHash, expiresAt]
  );

  res.json({ access_token: newAccess, refresh_token: newRefresh });
});

// ─────────────────────────────────────────────────────────────
// DELETE /api/v1/auth/logout
// ─────────────────────────────────────────────────────────────
router.delete('/logout', async (req, res) => {
  const { refresh_token } = req.body;
  if (refresh_token) {
    const hash = crypto.createHash('sha256').update(refresh_token).digest('hex');
    await pool.query(`DELETE FROM refresh_tokens WHERE token_hash = $1`, [hash]);
  }
  res.json({ message: 'Déconnecté avec succès.' });
});

module.exports = router;
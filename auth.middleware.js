const { verifyAccess, verifyTemp } = require('./jwt.utils');
const pool = require('./db');

/**
 * Middleware principal — vérifie l'access token JWT
 * Injecte req.user = { user_id, email }
 */
const requireAuth = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ error: 'Token manquant' });

  try {
    req.user = verifyAccess(header.split(' ')[1]);
    next();
  } catch {
    return res.status(401).json({ error: 'Token invalide ou expiré' });
  }
};

/**
 * Middleware — vérifie le token temporaire (étape OTP après login)
 * Injecte req.tempUser = { user_id, email }
 */
const requireTempToken = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ error: 'Token temporaire manquant' });

  try {
    req.tempUser = verifyTemp(header.split(' ')[1]);
    next();
  } catch {
    return res.status(401).json({ error: 'Token temporaire invalide ou expiré' });
  }
};

/**
 * Middleware — vérifie que l'utilisateur est actif en base
 */
const requireActiveUser = async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT statut FROM "user" WHERE user_id = $1`,
      [req.user.user_id]
    );
    if (!rows.length || rows[0].statut !== 'actif')
      return res.status(403).json({ error: 'Compte suspendu ou fermé' });
    next();
  } catch {
    return res.status(500).json({ error: 'Erreur serveur' });
  }
};

module.exports = { requireAuth, requireTempToken, requireActiveUser };

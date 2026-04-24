const express = require('express');
const pool    = require('./db');
const { requireAuth, requireActiveUser } = require('./auth.middleware');

const router = express.Router();

// GET /api/v1/account — Détail du compte principal (legacy)
router.get('/', requireAuth, requireActiveUser, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT a.account_id, a.rib, a.solde, a.devise,
              a.type_compte, a.statut, a.date_ouverture,
              a.plafond_journalier, a.created_at
       FROM account a
       WHERE a.user_id = $1`,
      [req.user.user_id]
    );

    if (!rows.length)
      return res.status(404).json({ error: 'Compte introuvable' });

    res.json({ account: rows[0] });
  } catch (err) {
    console.error('[account] GET /', err);
    res.status(500).json({ error: 'Erreur serveur interne.' });
  }
});

// GET /api/v1/account/all — Tous les comptes de l'utilisateur
router.get('/all', requireAuth, requireActiveUser, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT a.account_id, a.rib, a.solde, a.devise,
              a.type_compte, a.statut, a.date_ouverture,
              a.plafond_journalier, a.created_at
       FROM account a
       WHERE a.user_id = $1
       ORDER BY a.date_ouverture ASC`,
      [req.user.user_id]
    );

    res.json({ accounts: rows });
  } catch (err) {
    console.error('[account] GET /all', err);
    res.status(500).json({ error: 'Erreur serveur interne.' });
  }
});

// POST /api/v1/account — Créer un nouveau compte
router.post('/', requireAuth, requireActiveUser, async (req, res) => {
  const { type_compte = 'courant', devise = 'DZD' } = req.body;

  const allowedTypes   = ['courant', 'epargne'];
  const allowedDevises = ['DZD', 'EUR', 'USD', 'GBP'];

  if (!allowedTypes.includes(type_compte))
    return res.status(400).json({ error: 'Type de compte invalide.', code: 'INVALID_TYPE' });

  if (!allowedDevises.includes(devise))
    return res.status(400).json({ error: 'Devise non supportée.', code: 'INVALID_DEVISE' });

  try {
    // Check for duplicate type+devise combo
    const { rows: existing } = await pool.query(
      `SELECT 1 FROM account WHERE user_id = $1 AND type_compte = $2 AND devise = $3`,
      [req.user.user_id, type_compte, devise]
    );

    if (existing.length)
      return res.status(409).json({
        error: 'Vous possédez déjà un compte de ce type dans cette devise.',
        code: '23505',
      });

    // Generate RIB
    const rib = 'DZ' + Date.now() + Math.floor(Math.random() * 10000);

    const { rows } = await pool.query(
      `INSERT INTO account (user_id, rib, solde, devise, type_compte, statut, date_ouverture, plafond_journalier)
       VALUES ($1, $2, 0, $3, $4, 'actif', NOW(), 200000)
       RETURNING account_id, rib, solde, devise, type_compte, statut, date_ouverture`,
      [req.user.user_id, rib, devise, type_compte]
    );

    res.status(201).json({ account: rows[0] });

  } catch (err) {
    console.error('[account] POST /', err.code, err.message);

    // Enum value rejected by Postgres (should not happen after validation above, but just in case)
    if (err.code === '22P02') {
      return res.status(400).json({
        error: 'Valeur invalide pour le type de compte ou la devise.',
        code: err.code,
      });
    }

    // Unique constraint violation at DB level (fallback if app-level check races)
    if (err.code === '23505') {
      return res.status(409).json({
        error: 'Vous possédez déjà un compte de ce type dans cette devise.',
        code: err.code,
      });
    }

    res.status(500).json({ error: 'Erreur serveur interne.' });
  }
});

module.exports = router;
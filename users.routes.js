const express = require('express');
const pool    = require('./db');
const { requireAuth, requireActiveUser } = require('./auth.middleware');

const router = express.Router();

// ─────────────────────────────────────────────────────────────
// GET /api/v1/users/profile  — Profil complet
// ─────────────────────────────────────────────────────────────
router.get('/profile', requireAuth, requireActiveUser, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT
         user_id, nom, prenom, email,
         telephone, date_naissance, adresse,
         statut, kyc_valide, created_at, updated_at
       FROM "user"
       WHERE user_id = $1`,
      [req.user.user_id]
    );

    if (!rows.length)
      return res.status(404).json({ error: 'Utilisateur introuvable' });

    res.json({ profile: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─────────────────────────────────────────────────────────────
// PUT /api/v1/users/profile  — Modifier les données personnelles
// Champs modifiables : nom, prenom, telephone, adresse, date_naissance
// ─────────────────────────────────────────────────────────────
router.put('/profile', requireAuth, requireActiveUser, async (req, res) => {
  const { nom, prenom, telephone, adresse, date_naissance } = req.body;

  // Au moins un champ requis
  if (!nom && !prenom && !telephone && !adresse && !date_naissance)
    return res.status(400).json({ error: 'Aucun champ à mettre à jour' });

  try {
    // Construire la requête dynamiquement
    const updates = [];
    const values  = [];
    let idx = 1;

    if (nom)            { updates.push(`nom = $${idx++}`);            values.push(nom); }
    if (prenom)         { updates.push(`prenom = $${idx++}`);         values.push(prenom); }
    if (telephone)      { updates.push(`telephone = $${idx++}`);      values.push(telephone); }
    if (adresse)        { updates.push(`adresse = $${idx++}`);        values.push(adresse); }
    if (date_naissance) { updates.push(`date_naissance = $${idx++}`); values.push(date_naissance); }

    updates.push(`updated_at = NOW()`);
    values.push(req.user.user_id);

    const { rows } = await pool.query(
      `UPDATE "user" SET ${updates.join(', ')}
       WHERE user_id = $${idx}
       RETURNING user_id, nom, prenom, email, telephone, adresse, date_naissance, updated_at`,
      values
    );

    res.json({ message: 'Profil mis à jour.', profile: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;

const express = require('express');
const pool    = require('./db');
const { requireAuth, requireActiveUser } = require('./auth.middleware');

const router = express.Router();

// ─────────────────────────────────────────────────────────────
// GET /api/v1/notifications  — Lister les notifications
// Query params: statut (non_lu|lu|archivé|all), page, limit
// ─────────────────────────────────────────────────────────────
router.get('/', requireAuth, requireActiveUser, async (req, res) => {
  const { statut = 'all', page = 1, limit = 30 } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  try {
    let query = `
      SELECT notif_id, type, canal, titre, message,
             statut, entity_type, entity_id, lu_at, created_at
      FROM notification
      WHERE user_id = $1
    `;
    const params = [req.user.user_id];

    if (statut !== 'all') {
      query += ` AND statut = $2`;
      params.push(statut);
    }

    query += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(parseInt(limit), offset);

    const { rows }      = await pool.query(query, params);
    const { rows: cnt } = await pool.query(
      `SELECT COUNT(*) FROM notification WHERE user_id = $1 AND statut = 'non_lu'`,
      [req.user.user_id]
    );

    res.json({
      notifications: rows,
      unread_count: parseInt(cnt[0].count),
      page: parseInt(page),
      limit: parseInt(limit),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─────────────────────────────────────────────────────────────
// PATCH /api/v1/notifications/:id/read  — Marquer comme lue
// ─────────────────────────────────────────────────────────────
router.patch('/:id/read', requireAuth, requireActiveUser, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query(
      `UPDATE notification
       SET statut = 'lu', lu_at = NOW()
       WHERE notif_id = $1 AND user_id = $2 AND statut = 'non_lu'
       RETURNING notif_id, statut, lu_at`,
      [id, req.user.user_id]
    );

    if (!rows.length)
      return res.status(404).json({ error: 'Notification introuvable ou déjà lue' });

    res.json({ message: 'Notification marquée comme lue.', notification: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;

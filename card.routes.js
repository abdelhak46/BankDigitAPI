const express = require('express');
const pool    = require('./db');
const { requireAuth, requireActiveUser } = require('./auth.middleware');
const { verifyOtp, createOtp }           = require('./otp.utils');
const { sendOtpEmail }                   = require('./mailer');

const router = express.Router();

const httpError = (status, message) =>
  Object.assign(new Error(message), { httpStatus: status });

// ─── Card lookup helper ────────────────────────────────────────
const getUserCard = async (userId, dbClient = pool) => {
  const { rows } = await dbClient.query(
    `SELECT
       c.card_id,
       c.account_id,
       c.numero_carte        AS numero_masque,
       c.titulaire,
       c.statut::TEXT,
       c.type_carte::TEXT,
       c.reseau::TEXT,
       c.plafond_paiement,
       c.plafond_retrait,
       c.contactless,
       c.date_expiration,
       c.created_at          AS date_creation,
       a.devise
     FROM card c
     JOIN account a ON a.account_id = c.account_id
     WHERE a.user_id = $1
     ORDER BY
       CASE a.type_compte WHEN 'courant' THEN 0 ELSE 1 END,
       c.created_at ASC
     LIMIT 1`,
    [userId]
  );
  return rows[0] || null;
};

// ─────────────────────────────────────────────────────────────
// GET /api/v1/card  — Détail de la carte principale
// ─────────────────────────────────────────────────────────────
router.get('/', requireAuth, requireActiveUser, async (req, res) => {
  try {
    const card = await getUserCard(req.user.user_id);
    if (!card) return res.status(404).json({ error: 'Aucune carte associée à ce compte' });
    res.json({ card });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});


// ─────────────────────────────────────────────────────────────
// POST /api/v1/card/block  — Blocage immédiat (sans OTP)
//
// • Card must currently be active.
// • Immediate effect — no OTP required (emergency block UX).
// • Notification stored in-app.
// ─────────────────────────────────────────────────────────────
router.post('/block', requireAuth, requireActiveUser, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const card = await getUserCard(req.user.user_id, client);
    if (!card) throw httpError(404, 'Aucune carte associée à ce compte');
    if (card.statut === 'bloquée')
      throw httpError(400, 'La carte est déjà bloquée');
    if (card.statut !== 'active')
      throw httpError(400, `Impossible de bloquer une carte avec le statut : ${card.statut}`);

    await client.query(
      `UPDATE card SET statut = 'bloquée', updated_at = NOW() WHERE card_id = $1`,
      [card.card_id]
    );

    await client.query(
      `INSERT INTO notification (user_id, type, canal, titre, message, entity_type, entity_id)
       VALUES ($1,'carte','in_app','Carte bloquée 🔒',
               'Votre carte a été bloquée immédiatement. Tous les paiements et retraits sont désactivés.',
               'card',$2)`,
      [req.user.user_id, card.card_id]
    );

    await client.query('COMMIT');
    res.json({ message: 'Carte bloquée avec succès.', statut: 'bloquée' });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    if (err.httpStatus) return res.status(err.httpStatus).json({ error: err.message });
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  } finally {
    client.release();
  }
});


// ─────────────────────────────────────────────────────────────
// POST /api/v1/card/unblock  — Déblocage OTP-gated
//
// • Card must currently be bloquée.
// • First call (no otp_code): sends OTP email and returns 200.
// • Second call (with otp_code): verifies OTP, sets statut → 'active'.
// ─────────────────────────────────────────────────────────────
router.post('/unblock', requireAuth, requireActiveUser, async (req, res) => {
  const { otp_code } = req.body;

  // ── Step 1: Send OTP ────────────────────────────────────────
  if (!otp_code) {
    try {
      const card = await getUserCard(req.user.user_id);
      if (!card) return res.status(404).json({ error: 'Aucune carte associée à ce compte' });
      if (card.statut !== 'bloquée')
        return res.status(400).json({ error: 'La carte n\'est pas bloquée' });

      const code = await createOtp(req.user.user_id, 'card_action');
      await sendOtpEmail(req.user.email, code, 'card_action').catch(console.error);
      return res.json({ message: 'Code OTP envoyé. Relancez la requête avec otp_code.' });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: 'Erreur lors de l\'envoi du code OTP' });
    }
  }

  // ── Step 2: Verify OTP + unblock ───────────────────────────
  const otpResult = await verifyOtp(req.user.user_id, otp_code, 'card_action');
  if (!otpResult.valid) return res.status(401).json({ error: otpResult.reason });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const card = await getUserCard(req.user.user_id, client);
    if (!card) throw httpError(404, 'Aucune carte associée à ce compte');
    if (card.statut !== 'bloquée')
      throw httpError(400, 'La carte n\'est pas bloquée');

    await client.query(
      `UPDATE card SET statut = 'active', updated_at = NOW() WHERE card_id = $1`,
      [card.card_id]
    );

    await client.query(
      `INSERT INTO notification (user_id, type, canal, titre, message, entity_type, entity_id)
       VALUES ($1,'carte','in_app','Carte débloquée 🔓',
               'Votre carte a été débloquée. Paiements et retraits sont à nouveau disponibles.',
               'card',$2)`,
      [req.user.user_id, card.card_id]
    );

    await client.query('COMMIT');
    res.json({ message: 'Carte débloquée avec succès.', statut: 'active' });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    if (err.httpStatus) return res.status(err.httpStatus).json({ error: err.message });
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  } finally {
    client.release();
  }
});


// ─────────────────────────────────────────────────────────────
// POST /api/v1/card/activate  — Activation OTP-gated
//
// • Intended for cards in statut 'inactive' or 'bloquée'.
// • First call (no otp_code): sends OTP email and returns 200.
// • Second call (with otp_code): verifies OTP, sets statut → 'active'.
// ─────────────────────────────────────────────────────────────
router.post('/activate', requireAuth, requireActiveUser, async (req, res) => {
  const { otp_code } = req.body;

  // ── Step 1: Send OTP ────────────────────────────────────────
  if (!otp_code) {
    try {
      const card = await getUserCard(req.user.user_id);
      if (!card) return res.status(404).json({ error: 'Aucune carte associée à ce compte' });
      if (card.statut === 'active')
        return res.status(400).json({ error: 'La carte est déjà active' });

      const code = await createOtp(req.user.user_id, 'card_action');
      await sendOtpEmail(req.user.email, code, 'card_action').catch(console.error);
      return res.json({ message: 'Code OTP envoyé. Relancez la requête avec otp_code.' });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ error: 'Erreur lors de l\'envoi du code OTP' });
    }
  }

  // ── Step 2: Verify OTP + activate ──────────────────────────
  const otpResult = await verifyOtp(req.user.user_id, otp_code, 'card_action');
  if (!otpResult.valid) return res.status(401).json({ error: otpResult.reason });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const card = await getUserCard(req.user.user_id, client);
    if (!card) throw httpError(404, 'Aucune carte associée à ce compte');
    if (card.statut === 'active')
      throw httpError(400, 'La carte est déjà active');

    await client.query(
      `UPDATE card SET statut = 'active', updated_at = NOW() WHERE card_id = $1`,
      [card.card_id]
    );

    await client.query(
      `INSERT INTO notification (user_id, type, canal, titre, message, entity_type, entity_id)
       VALUES ($1,'carte','in_app','Carte activée ✅',
               'Votre carte est maintenant active et prête à l\'emploi.',
               'card',$2)`,
      [req.user.user_id, card.card_id]
    );

    await client.query('COMMIT');
    res.json({ message: 'Carte activée avec succès.', statut: 'active' });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    if (err.httpStatus) return res.status(err.httpStatus).json({ error: err.message });
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  } finally {
    client.release();
  }
});

module.exports = router;
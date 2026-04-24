const express = require('express');
const crypto  = require('crypto');
const https   = require('https');
const pool    = require('./db');
const { requireAuth, requireActiveUser } = require('./auth.middleware');
const { verifyOtp, createOtp }           = require('./otp.utils');
const { sendOtpEmail }                   = require('./mailer');

const router = express.Router();

/*
 * ─── DB MIGRATION REQUIRED ────────────────────────────────────────────────────
 * Run once before deploying this version:
 *
 *   ALTER TABLE transfert_intern
 *     ADD COLUMN IF NOT EXISTS taux_change      NUMERIC(18,6),
 *     ADD COLUMN IF NOT EXISTS montant_credite  NUMERIC(18,2),
 *     ADD COLUMN IF NOT EXISTS devise_dest      VARCHAR(10);
 *
 *   ALTER TABLE transfert_externe
 *     ADD COLUMN IF NOT EXISTS justificatif     TEXT,
 *     ADD COLUMN IF NOT EXISTS taux_change      NUMERIC(18,6),
 *     ADD COLUMN IF NOT EXISTS montant_credite  NUMERIC(18,2);
 * ──────────────────────────────────────────────────────────────────────────────
 */

const httpError = (status, message) =>
  Object.assign(new Error(message), { httpStatus: status });

// ─── Exchange rate helper (open.er-api.com — free, no key) ────
const getExchangeRate = (from, to) => {
  if (from === to) return Promise.resolve(1);
  return new Promise((resolve, reject) => {
    https.get(`https://open.er-api.com/v6/latest/${encodeURIComponent(from)}`, (res) => {
      let body = '';
      res.on('data', d => (body += d));
      res.on('end', () => {
        try {
          const json = JSON.parse(body);
          if (json.result === 'success' && json.rates?.[to]) {
            resolve(parseFloat(json.rates[to]));
          } else {
            reject(httpError(502, `Taux de change ${from}→${to} introuvable`));
          }
        } catch {
          reject(httpError(502, 'Erreur de lecture du taux de change'));
        }
      });
    }).on('error', () => reject(httpError(502, 'Service de taux de change indisponible')));
  });
};

// ─── Account lookup helper ─────────────────────────────────────
const getUserAccount = async (userId, accountId = null, dbClient = pool) => {
  if (accountId) {
    const { rows } = await dbClient.query(
      `SELECT account_id, solde, statut, rib, devise, type_compte
       FROM account WHERE account_id = $1 AND user_id = $2`,
      [accountId, userId]
    );
    return rows[0] || null;
  }
  const { rows } = await dbClient.query(
    `SELECT account_id, solde, statut, rib, devise, type_compte
     FROM account WHERE user_id = $1
     ORDER BY CASE type_compte WHEN 'courant' THEN 0 ELSE 1 END, created_at ASC
     LIMIT 1`,
    [userId]
  );
  return rows[0] || null;
};

const genRef = () => 'TXN-' + crypto.randomBytes(8).toString('hex').toUpperCase();

// Schedules background completion. setTimeout is fine for demo/single-process;
// swap for pg-cron or a message queue in production.
const scheduleCompletion = (transferId, table, delayMs) => {
  setTimeout(() => {
    pool.query(
      `UPDATE ${table} SET statut = 'validé', completed_at = NOW() WHERE transfert_id = $1`,
      [transferId]
    ).catch(e => console.error(`[scheduleCompletion] ${table}/${transferId}:`, e));
  }, delayMs);
};


// ─────────────────────────────────────────────────────────────
// GET /api/v1/exchange-rate?from=DZD&to=EUR
// Frontend uses this for live conversion previews before submitting.
// ─────────────────────────────────────────────────────────────
router.get('/exchange-rate', requireAuth, async (req, res) => {
  const { from, to } = req.query;
  if (!from || !to)
    return res.status(400).json({ error: 'Paramètres from et to requis' });
  try {
    const rate = await getExchangeRate(from.toUpperCase(), to.toUpperCase());
    res.json({ from: from.toUpperCase(), to: to.toUpperCase(), rate });
  } catch (err) {
    if (err.httpStatus) return res.status(err.httpStatus).json({ error: err.message });
    res.status(500).json({ error: 'Erreur serveur' });
  }
});


// ─────────────────────────────────────────────────────────────
// POST /api/v1/transfers_own  — Virement entre ses propres comptes
//
// • Both accounts must belong to the authenticated user.
// • Cross-currency supported: source debited in source.devise,
//   destination credited with the converted amount.
// • Rate fetched live at submission time and stored in taux_change.
// • No fees — the user is moving their own money.
// • Immediate status: 'validé'.
// ─────────────────────────────────────────────────────────────
router.post('/transfers_own', requireAuth, requireActiveUser, async (req, res) => {
  const { account_id_source, account_id_dest, montant, motif, otp_code } = req.body;

  if (!account_id_dest || !montant)
    return res.status(400).json({ error: 'account_id_dest et montant sont requis' });
  if (parseFloat(montant) <= 0)
    return res.status(400).json({ error: 'Le montant doit être positif' });

  if (!otp_code) {
    const code = await createOtp(req.user.user_id, 'transfer');
    await sendOtpEmail(req.user.email, code, 'transfer').catch(console.error);
    return res.json({ message: 'Code OTP envoyé. Relancez la requête avec otp_code.' });
  }

  const otpResult = await verifyOtp(req.user.user_id, otp_code, 'transfer');
  if (!otpResult.valid) return res.status(401).json({ error: otpResult.reason });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const sourceAccount = await getUserAccount(req.user.user_id, account_id_source || null, client);
    if (!sourceAccount) throw httpError(404, 'Compte source introuvable');
    if (sourceAccount.statut !== 'actif') throw httpError(403, 'Compte source bloqué');

    const { rows: destRows } = await client.query(
      `SELECT account_id, solde, statut, rib, devise, type_compte
       FROM account WHERE account_id = $1 AND user_id = $2`,
      [account_id_dest, req.user.user_id]
    );
    if (!destRows.length) throw httpError(404, 'Compte destinataire introuvable');
    const destAccount = destRows[0];

    if (sourceAccount.account_id === destAccount.account_id)
      throw httpError(400, 'Source et destination identiques');
    if (destAccount.statut !== 'actif')
      throw httpError(403, 'Compte destinataire bloqué');
    if (parseFloat(sourceAccount.solde) < parseFloat(montant))
      throw httpError(400, 'Solde insuffisant');

    // ── Live conversion ────────────────────────────────────────
    const taux           = await getExchangeRate(sourceAccount.devise, destAccount.devise);
    const montantCredite = (parseFloat(montant) * taux).toFixed(2);
    const isCross        = sourceAccount.devise !== destAccount.devise;

    const motifFinal = (motif || 'Virement entre mes comptes') +
      (isCross
        ? ` [Converti: ${montant} ${sourceAccount.devise} → ${montantCredite} ${destAccount.devise} @ ${taux}]`
        : '');

    const reference = genRef();

    const { rows: [transfer] } = await client.query(
      `INSERT INTO transfert_intern
         (account_source_id, account_dest_id, montant, devise, motif, statut, reference,
          frais, taux_change, montant_credite, devise_dest)
       VALUES ($1,$2,$3,$4,$5,'validé',$6,0,$7,$8,$9)
       RETURNING transfert_id, reference, statut, initiated_at`,
      [sourceAccount.account_id, destAccount.account_id,
       montant, sourceAccount.devise, motifFinal, reference,
       taux, montantCredite, destAccount.devise]
    );

    await client.query(
      `UPDATE account SET solde = solde - $1, updated_at = NOW() WHERE account_id = $2`,
      [montant, sourceAccount.account_id]
    );
    await client.query(
      `UPDATE account SET solde = solde + $1, updated_at = NOW() WHERE account_id = $2`,
      [montantCredite, destAccount.account_id]
    );

    const notifMsg = isCross
      ? `${montant} ${sourceAccount.devise} converti et crédité en ${montantCredite} ${destAccount.devise} (compte ${destAccount.type_compte}).`
      : `${montant} ${sourceAccount.devise} transféré vers votre compte ${destAccount.type_compte}.`;

    await client.query(
      `INSERT INTO notification (user_id, type, canal, titre, message, entity_type, entity_id)
       VALUES ($1,'transfert_intern','in_app','Virement entre comptes ✅',$2,'transfert_intern',$3)`,
      [req.user.user_id, notifMsg, transfer.transfert_id]
    );

    await client.query('COMMIT');
    res.status(201).json({
      message: 'Virement entre comptes effectué.',
      transfer: {
        ...transfer,
        devise:          sourceAccount.devise,
        devise_dest:     destAccount.devise,
        taux_change:     taux,
        montant_credite: montantCredite,
        is_cross_devise: isCross,
      },
    });
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
// POST /api/v1/transfers_interen  — Virement interne (même banque, autre personne)
//
// • Destination identified by RIB within the same bank.
// • Same currency required — no cross-currency between third parties.
// • No fees.
// • Immediate status: 'validé'.
// ─────────────────────────────────────────────────────────────
router.post('/transfers_interen', requireAuth, requireActiveUser, async (req, res) => {
  const { rib_destinataire, montant, motif, otp_code, account_id_source } = req.body;

  if (!rib_destinataire || !montant)
    return res.status(400).json({ error: 'rib_destinataire et montant sont requis' });
  if (parseFloat(montant) <= 0)
    return res.status(400).json({ error: 'Le montant doit être positif' });

  if (!otp_code) {
    const code = await createOtp(req.user.user_id, 'transfer');
    await sendOtpEmail(req.user.email, code, 'transfer').catch(console.error);
    return res.json({ message: 'Code OTP envoyé. Relancez la requête avec otp_code.' });
  }

  const otpResult = await verifyOtp(req.user.user_id, otp_code, 'transfer');
  if (!otpResult.valid) return res.status(401).json({ error: otpResult.reason });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const sourceAccount = await getUserAccount(req.user.user_id, account_id_source || null, client);
    if (!sourceAccount) throw httpError(404, 'Compte source introuvable');
    if (sourceAccount.statut !== 'actif') throw httpError(403, 'Compte source bloqué');

    const { rows: destRows } = await client.query(
      `SELECT account_id, statut, devise FROM account WHERE rib = $1`,
      [rib_destinataire]
    );
    if (!destRows.length) throw httpError(404, 'RIB destinataire introuvable');
    const destAccount = destRows[0];

    if (sourceAccount.account_id === destAccount.account_id)
      throw httpError(400, 'Source et destination identiques');

    // ── Same currency rule ─────────────────────────────────────
    if (sourceAccount.devise !== destAccount.devise)
      throw httpError(400,
        `Devise incompatible : votre compte est en ${sourceAccount.devise} ` +
        `mais le compte destinataire est en ${destAccount.devise}. ` +
        `Les deux comptes doivent être dans la même devise.`
      );

    if (parseFloat(sourceAccount.solde) < parseFloat(montant))
      throw httpError(400, 'Solde insuffisant');

    const devise    = sourceAccount.devise;
    const reference = genRef();

    const { rows: [transfer] } = await client.query(
      `INSERT INTO transfert_intern
         (account_source_id, account_dest_id, montant, devise, motif, statut, reference, frais)
       VALUES ($1,$2,$3,$4,$5,'validé',$6,0)
       RETURNING transfert_id, reference, statut, initiated_at`,
      [sourceAccount.account_id, destAccount.account_id, montant, devise, motif || null, reference]
    );

    await client.query(
      `UPDATE account SET solde = solde - $1, updated_at = NOW() WHERE account_id = $2`,
      [montant, sourceAccount.account_id]
    );
    await client.query(
      `UPDATE account SET solde = solde + $1, updated_at = NOW() WHERE account_id = $2`,
      [montant, destAccount.account_id]
    );

    await client.query(
      `INSERT INTO notification (user_id, type, canal, titre, message, entity_type, entity_id)
       VALUES ($1,'transfert_intern','in_app','Virement effectué ✅',$2,'transfert_intern',$3)`,
      [req.user.user_id,
       `Virement de ${montant} ${devise} effectué vers ${rib_destinataire}.`,
       transfer.transfert_id]
    );

    await client.query('COMMIT');
    res.status(201).json({ message: 'Virement effectué.', transfer: { ...transfer, devise } });
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
// POST /api/v1/transfers_externe  — Virement externe Algérie
//
// • Transfers to a different Algerian bank (pays_destinataire = 'DZ').
// • Same currency as the source account — no FX conversion.
// • No fees for local inter-bank transfers.
// • Status: 'en_attente' immediately; auto-flips to 'validé' after 24 h (simulation).
// ─────────────────────────────────────────────────────────────
router.post('/transfers_externe', requireAuth, requireActiveUser, async (req, res) => {
  const {
    rib_destinataire, nom_destinataire, banque_destinataire,
    montant, motif, otp_code, account_id_source,
  } = req.body;

  if (!rib_destinataire || !nom_destinataire || !montant)
    return res.status(400).json({
      error: 'rib_destinataire, nom_destinataire et montant sont requis',
    });
  if (parseFloat(montant) <= 0)
    return res.status(400).json({ error: 'Montant invalide' });

  if (!otp_code) {
    const code = await createOtp(req.user.user_id, 'transfer');
    await sendOtpEmail(req.user.email, code, 'transfer').catch(console.error);
    return res.json({ message: 'Code OTP envoyé. Relancez la requête avec otp_code.' });
  }

  const otpResult = await verifyOtp(req.user.user_id, otp_code, 'transfer');
  if (!otpResult.valid) return res.status(401).json({ error: otpResult.reason });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const sourceAccount = await getUserAccount(req.user.user_id, account_id_source || null, client);
    if (!sourceAccount) throw httpError(404, 'Compte introuvable');
    if (sourceAccount.statut !== 'actif') throw httpError(403, 'Compte bloqué');

    if (parseFloat(sourceAccount.solde) < parseFloat(montant))
      throw httpError(400, 'Solde insuffisant');

    const devise    = sourceAccount.devise;
    const reference = genRef();

    const { rows: [transfer] } = await client.query(
      `INSERT INTO transfert_externe
         (account_source_id, iban_destinataire, nom_destinataire,
          banque_destinataire, pays_destinataire, montant, devise, motif,
          statut, reference, frais, canal)
       VALUES ($1,$2,$3,$4,'DZ',$5,$6,$7,'en_attente',$8,0,'VIREMENT_LOCAL')
       RETURNING transfert_id, reference, statut, frais, initiated_at`,
      [sourceAccount.account_id, rib_destinataire, nom_destinataire,
       banque_destinataire || null, montant, devise, motif || null, reference]
    );

    // Debit immediately — funds held during processing
    await client.query(
      `UPDATE account SET solde = solde - $1, updated_at = NOW() WHERE account_id = $2`,
      [montant, sourceAccount.account_id]
    );

    await client.query(
      `INSERT INTO notification (user_id, type, canal, titre, message, entity_type, entity_id)
       VALUES ($1,'transfert_externe','in_app','Virement local soumis 🏦',$2,'transfert_externe',$3)`,
      [req.user.user_id,
       `Virement de ${montant} ${devise} vers ${nom_destinataire} en cours (délai estimé : 24h).`,
       transfer.transfert_id]
    );

    await client.query('COMMIT');

    // ── Simulation: validé after 24 hours ─────────────────────
    scheduleCompletion(transfer.transfert_id, 'transfert_externe', 24 * 60 * 60 * 1000);

    res.status(201).json({
      message: 'Virement local soumis (traitement sous 24h).',
      transfer: { ...transfer, devise },
    });
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
// POST /api/v1/transfers_international  — Virement international
//
// • Source account must be EUR or USD (DZD not eligible per regulation).
// • justificatif (document) is REQUIRED — submission rejected without it.
// • Cross-currency allowed: live rate fetched and locked at submission.
// • Fees: 1.5% base + 0.5% FX spread when source.devise ≠ dest devise.
// • Status: 'en_attente' → auto-flips to 'validé' after 2–5 days (simulation).
// ─────────────────────────────────────────────────────────────
router.post('/transfers_international', requireAuth, requireActiveUser, async (req, res) => {
  const {
    iban_destinataire, bic_swift, nom_destinataire, banque_destinataire,
    pays_destinataire, montant, devise = 'EUR', motif, canal = 'SWIFT',
    otp_code, account_id_source, justificatif,
  } = req.body;

  if (!iban_destinataire || !nom_destinataire || !pays_destinataire || !montant)
    return res.status(400).json({ error: 'Champs obligatoires manquants' });
  if (!justificatif)
    return res.status(400).json({
      error: 'Un document justificatif est obligatoire pour les virements internationaux.',
    });
  if (parseFloat(montant) <= 0)
    return res.status(400).json({ error: 'Montant invalide' });

  if (!otp_code) {
    const code = await createOtp(req.user.user_id, 'transfer');
    await sendOtpEmail(req.user.email, code, 'transfer').catch(console.error);
    return res.json({ message: 'Code OTP envoyé. Relancez la requête avec otp_code.' });
  }

  const otpResult = await verifyOtp(req.user.user_id, otp_code, 'transfer');
  if (!otpResult.valid) return res.status(401).json({ error: otpResult.reason });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const sourceAccount = await getUserAccount(req.user.user_id, account_id_source || null, client);
    if (!sourceAccount) throw httpError(404, 'Compte introuvable');
    if (sourceAccount.statut !== 'actif') throw httpError(403, 'Compte bloqué');

    // ── EUR / USD only ─────────────────────────────────────────
    if (!['EUR', 'USD'].includes(sourceAccount.devise))
      throw httpError(400,
        `Les virements internationaux nécessitent un compte en EUR ou USD. ` +
        `Votre compte source est en ${sourceAccount.devise}.`
      );

    // ── Live conversion ────────────────────────────────────────
    const deviseSource    = sourceAccount.devise;
    const deviseDest      = devise.toUpperCase();
    const taux            = await getExchangeRate(deviseSource, deviseDest);
    const montantConverti = (parseFloat(montant) * taux).toFixed(2);
    const isCross         = deviseSource !== deviseDest;

    // ── Fees: 1.5% base, +0.5% FX spread when cross-currency ──
    const feeRate    = isCross ? 0.02 : 0.015;
    const frais      = (parseFloat(montant) * feeRate).toFixed(2);
    const totalDebit = (parseFloat(montant) + parseFloat(frais)).toFixed(2);

    if (parseFloat(sourceAccount.solde) < parseFloat(totalDebit))
      throw httpError(400,
        `Solde insuffisant. Montant + frais (${(feeRate * 100).toFixed(1)}%) = ${totalDebit} ${deviseSource}.`
      );

    const reference     = genRef();
    // Cap the stored justificatif reference at 512 chars (full file content should go to object storage)
    const justificatifRef = String(justificatif).substring(0, 512);

    const { rows: [transfer] } = await client.query(
      `INSERT INTO transfert_externe
         (account_source_id, iban_destinataire, bic_swift, nom_destinataire,
          banque_destinataire, pays_destinataire, montant, devise, motif,
          statut, reference, frais, canal, justificatif, taux_change, montant_credite)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'en_attente',$10,$11,$12,$13,$14,$15)
       RETURNING transfert_id, reference, statut, frais, initiated_at`,
      [sourceAccount.account_id, iban_destinataire, bic_swift || null,
       nom_destinataire, banque_destinataire || null, pays_destinataire,
       montant, deviseDest, motif || null,
       reference, frais, canal,
       justificatifRef, taux, montantConverti]
    );

    // Debit montant + frais from source account
    await client.query(
      `UPDATE account SET solde = solde - $1, updated_at = NOW() WHERE account_id = $2`,
      [totalDebit, sourceAccount.account_id]
    );

    const notifMsg = isCross
      ? `${montant} ${deviseSource} → ${montantConverti} ${deviseDest} vers ${nom_destinataire} (${pays_destinataire}) en cours de validation.`
      : `${montant} ${deviseSource} vers ${nom_destinataire} (${pays_destinataire}) en cours de validation.`;

    await client.query(
      `INSERT INTO notification (user_id, type, canal, titre, message, entity_type, entity_id)
       VALUES ($1,'transfert_externe','in_app','Virement international soumis 🌍',$2,'transfert_externe',$3)`,
      [req.user.user_id, notifMsg, transfer.transfert_id]
    );

    await client.query('COMMIT');

    // ── Simulation: validé after 2–5 business days ─────────────
    const days = 2 + Math.floor(Math.random() * 4);
    scheduleCompletion(transfer.transfert_id, 'transfert_externe', days * 24 * 60 * 60 * 1000);

    res.status(201).json({
      message: `Virement international soumis. Traitement estimé sous ${days} jours ouvrés.`,
      transfer: {
        ...transfer,
        devise:           deviseDest,
        devise_source:    deviseSource,
        taux_change:      taux,
        montant_converti: montantConverti,
        frais,
        total_debite:     totalDebit,
        is_cross_devise:  isCross,
      },
    });
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
// GET /api/v1/transfers  — Historique des virements
// type query param: 'all' | 'intern' | 'extern'
// ─────────────────────────────────────────────────────────────
router.get('/transfers', requireAuth, requireActiveUser, async (req, res) => {
  const { type = 'all', page = 1, limit = 20 } = req.query;
  const parsedLimit = parseInt(limit);
  const offset      = (parseInt(page) - 1) * parsedLimit;

  try {
    const { rows: accRows } = await pool.query(
      `SELECT account_id FROM account WHERE user_id = $1`,
      [req.user.user_id]
    );
    if (!accRows.length) return res.status(404).json({ error: 'Compte introuvable' });

    const accountIds = accRows.map(r => r.account_id);
    let intern = [], externe = [];

    if (type === 'all' || type === 'intern') {
      const { rows } = await pool.query(
        `SELECT transfert_id, account_source_id, account_dest_id, montant, devise,
                devise_dest, taux_change, montant_credite,
                motif, statut, reference, frais, initiated_at, completed_at, 'intern' AS type
         FROM transfert_intern
         WHERE account_source_id = ANY($1::uuid[]) OR account_dest_id = ANY($1::uuid[])
         ORDER BY initiated_at DESC LIMIT $2 OFFSET $3`,
        [accountIds, parsedLimit, offset]
      );
      intern = rows;
    }

    if (type === 'all' || type === 'extern') {
      const { rows } = await pool.query(
        `SELECT transfert_id, account_source_id, iban_destinataire, nom_destinataire,
                montant, devise, motif, statut, reference, frais, canal,
                pays_destinataire, taux_change, montant_credite,
                initiated_at, completed_at, 'extern' AS type
         FROM transfert_externe
         WHERE account_source_id = ANY($1::uuid[])
         ORDER BY initiated_at DESC LIMIT $2 OFFSET $3`,
        [accountIds, parsedLimit, offset]
      );
      externe = rows;
    }

    const all = [...intern, ...externe]
      .sort((a, b) => new Date(b.initiated_at) - new Date(a.initiated_at))
      .slice(0, parsedLimit);

    res.json({ transfers: all, page: parseInt(page), limit: parsedLimit });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});


// ─────────────────────────────────────────────────────────────
// GET /api/v1/transfers/:id  — Détail d'un virement
// ─────────────────────────────────────────────────────────────
router.get('/transfers/:id', requireAuth, requireActiveUser, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows: accRows } = await pool.query(
      `SELECT account_id FROM account WHERE user_id = $1`,
      [req.user.user_id]
    );
    if (!accRows.length) return res.status(404).json({ error: 'Compte introuvable' });

    const accountIds = accRows.map(r => r.account_id);
    let transfer = null;

    const { rows: intern } = await pool.query(
      `SELECT *, 'intern' AS type FROM transfert_intern
       WHERE transfert_id = $1
         AND (account_source_id = ANY($2::uuid[]) OR account_dest_id = ANY($2::uuid[]))`,
      [id, accountIds]
    );
    if (intern.length) transfer = intern[0];

    if (!transfer) {
      const { rows: externe } = await pool.query(
        `SELECT *, 'extern' AS type FROM transfert_externe
         WHERE transfert_id = $1 AND account_source_id = ANY($2::uuid[])`,
        [id, accountIds]
      );
      if (externe.length) transfer = externe[0];
    }

    if (!transfer) return res.status(404).json({ error: 'Virement introuvable' });
    res.json({ transfer });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;
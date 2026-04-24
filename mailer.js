const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: false, // true pour port 465
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

/**
 * Envoie un email OTP à l'utilisateur
 * @param {string} to - Adresse destinataire
 * @param {string} code - Code OTP à 6 chiffres
 * @param {string} purpose - 'login' | 'transfer' | 'card_action'
 */
const sendOtpEmail = async (to, code, purpose = 'login') => {
  const subjects = {
    login:       '🔐 Votre code de connexion BankDigit',
    transfer:    '💸 Confirmation de virement BankDigit',
    card_action: '💳 Confirmation action carte BankDigit',
  };

  const subject = subjects[purpose] || '🔑 Code de vérification BankDigit';

  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to,
    subject,
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px;border:1px solid #e5e7eb;border-radius:12px;">
        <h2 style="color:#1d4ed8;margin-bottom:8px;">BankDigit</h2>
        <p style="color:#374151;">Votre code de vérification est :</p>
        <div style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#1d4ed8;
                    background:#eff6ff;padding:16px 24px;border-radius:8px;
                    text-align:center;margin:16px 0;">
          ${code}
        </div>
        <p style="color:#6b7280;font-size:13px;">
          Ce code est valable <strong>5 minutes</strong>.<br>
          Ne le partagez jamais avec personne.
        </p>
      </div>
    `,
  });
};

/**
 * Envoie un email de vérification d'adresse à l'inscription
 */
const sendVerifyEmail = async (to, verifyUrl) => {
  await transporter.sendMail({
    from: process.env.EMAIL_FROM,
    to,
    subject: '✅ Vérifiez votre adresse email — BankDigit',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px;border:1px solid #e5e7eb;border-radius:12px;">
        <h2 style="color:#1d4ed8;">BankDigit</h2>
        <p>Cliquez sur le bouton ci-dessous pour vérifier votre adresse email.</p>
        <a href="${verifyUrl}"
           style="display:inline-block;background:#1d4ed8;color:#fff;padding:12px 24px;
                  border-radius:8px;text-decoration:none;font-weight:bold;margin:16px 0;">
          Vérifier mon email
        </a>
        <p style="color:#6b7280;font-size:13px;">Ce lien expire dans 24 heures.</p>
      </div>
    `,
  });
};

module.exports = { sendOtpEmail, sendVerifyEmail };

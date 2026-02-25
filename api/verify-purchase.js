/**
 * /api/verify-purchase.js
 * Vercel Serverless Function
 *
 * Google Play サブスク購入の検証 & acknowledge
 *
 * Required env vars:
 *   GOOGLE_SERVICE_ACCOUNT_EMAIL
 *   GOOGLE_SERVICE_ACCOUNT_KEY   (JSON の private_key 値、\\n 保持)
 *   GOOGLE_PACKAGE_NAME          (例: app.vercel.twd_jpy.twa)
 *   ALLOWED_ORIGINS              (カンマ区切り、末尾スラッシュなし、例: https://twd-jpy.vercel.app)
 */

const crypto = require('crypto');

/* --- SKU whitelist (別々の productId 運用) --- */
const ALLOWED_SKUS = [
  'twd_jpy_premium_weekly',
  'twd_jpy_premium_yearly',
];

/* --- 有効な subscription state --- */
const VALID_STATES = [
  'SUBSCRIPTION_STATE_ACTIVE',
  'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
];

/* --- base64url (Node <15 互換) --- */
function toBase64Url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* --- Origin / Referer チェック --- */
function checkOrigin(req) {
  const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!allowed.length) return true;

  const origin = req.headers['origin'];
  const referer = req.headers['referer'];

  // デバッグログ（TWAでの実際の値を確認後、削除してOK）
  console.log('[checkOrigin]', { origin: origin || '(empty)', referer: referer || '(empty)' });

  if (origin) return allowed.includes(origin);

  if (referer) {
    try {
      const u = new URL(referer);
      return allowed.includes(u.origin);
    } catch { return false; }
  }

  // どちらもない場合は通す（TWA内では両方空になりうる）
  return true;
}

/* --- JWT → access token --- */
async function getAccessToken() {
  const email = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
  if (!email) throw new Error('GOOGLE_SERVICE_ACCOUNT_EMAIL not set');

  const keyRaw = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
  if (!keyRaw) throw new Error('GOOGLE_SERVICE_ACCOUNT_KEY not set');
  const key = keyRaw.replace(/\\n/g, '\n');

  const now = Math.floor(Date.now() / 1000);

  const header = toBase64Url(Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const payload = toBase64Url(Buffer.from(JSON.stringify({
    iss: email,
    scope: 'https://www.googleapis.com/auth/androidpublisher',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  })));

  const sign = crypto.createSign('RSA-SHA256');
  sign.update(header + '.' + payload);
  const signature = toBase64Url(sign.sign(key));

  const jwt = header + '.' + payload + '.' + signature;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=' + jwt,
  });
  const data = await res.json();
  if (!data.access_token) throw new Error('Token fetch failed: ' + JSON.stringify(data));
  return data.access_token;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed', valid: false });
  }

  if (!checkOrigin(req)) {
    return res.status(403).json({ error: 'Forbidden', valid: false });
  }

  const { purchaseToken, sku } = req.body || {};

  if (!purchaseToken || !sku) {
    return res.status(400).json({ error: 'Missing purchaseToken or sku', valid: false });
  }
  if (!ALLOWED_SKUS.includes(sku)) {
    return res.status(400).json({ error: 'Invalid sku', valid: false });
  }

  const packageName = process.env.GOOGLE_PACKAGE_NAME;
  if (!packageName) {
    return res.status(500).json({ error: 'Server config error', valid: false });
  }

  try {
    const accessToken = await getAccessToken();

    /* Step 1: subscriptionsv2.get で検証 */
    const verifyUrl =
      `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/subscriptionsv2/tokens/${purchaseToken}`;

    const verifyRes = await fetch(verifyUrl, {
      headers: { Authorization: 'Bearer ' + accessToken },
    });

    if (!verifyRes.ok) {
      const txt = await verifyRes.text().catch(() => '');
      console.error('[verify] HTTP error:', verifyRes.status, txt);
      return res.status(400).json({ valid: false, error: 'Verify HTTP ' + verifyRes.status });
    }

    const sub = await verifyRes.json();

    if (sub.error) {
      console.error('[verify] API error:', sub.error);
      return res.status(400).json({ valid: false, error: sub.error.message });
    }

    const state = sub.subscriptionState || '';
    if (!VALID_STATES.includes(state)) {
      console.log('[verify] Rejected state:', state);
      return res.status(400).json({ valid: false, error: 'Subscription not active: ' + state });
    }

    const lineItems = sub.lineItems || [];
    const matchedItem = lineItems.find(li => li.productId === sku);
    if (!matchedItem) {
      return res.status(400).json({ valid: false, error: 'SKU mismatch' });
    }

    /* Step 2: 未 ack なら acknowledge */
    if (sub.acknowledgementState === 'ACKNOWLEDGEMENT_STATE_PENDING') {
      const ackUrl =
        `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/subscriptions/${sku}/tokens/${purchaseToken}:acknowledge`;

      const ackRes = await fetch(ackUrl, {
        method: 'POST',
        headers: {
          Authorization: 'Bearer ' + accessToken,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      });

      if (!ackRes.ok) {
        const ackErr = await ackRes.text();
        console.error('[verify] Ack failed:', ackRes.status, ackErr);
        return res.status(500).json({ valid: false, error: 'Acknowledge failed' });
      }
    }

    return res.status(200).json({ valid: true, state: state });

  } catch (e) {
    console.error('[verify] Error:', e);
    return res.status(500).json({ valid: false, error: 'Server error' });
  }
};

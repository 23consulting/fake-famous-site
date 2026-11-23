// Netlify Function: receives Paddle Billing webhooks and verifies their signature.
// Endpoint after deploy: https://YOURDOMAIN/.netlify/functions/paddle-webhook
// Set PADDLE_WEBHOOK_SECRET in Netlify (Site settings > Environment variables).
// In Paddle: Developer tools > Notifications > add this URL and subscribe to
// transaction.completed, subscription.created, subscription.activated,
// subscription.updated and subscription.canceled.

const crypto = require('crypto');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return { statusCode: 405, body: 'Method not allowed' };

  const secret = process.env.PADDLE_WEBHOOK_SECRET;
  const raw = event.isBase64Encoded ? Buffer.from(event.body, 'base64').toString('utf8') : event.body;
  const header = event.headers['paddle-signature'] || '';

  const parts = {};
  header.split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) parts[p.slice(0, i)] = p.slice(i + 1);
  });
  const { ts, h1 } = parts;
  if (!secret || !ts || !h1) return { statusCode: 400, body: 'Missing signature' };

  // Reject requests older than 5 minutes.
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return { statusCode: 400, body: 'Stale request' };

  const expected = crypto.createHmac('sha256', secret).update(`${ts}:${raw}`).digest('hex');
  const a = Buffer.from(expected);
  const b = Buffer.from(h1);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { statusCode: 400, body: 'Invalid signature' };
  }

  const payload = JSON.parse(raw);
  const data = payload.data || {};

  switch (payload.event_type) {
    case 'subscription.activated':
    case 'subscription.created':
    case 'transaction.completed':
      // TODO: mark the customer as Pro in your database.
      // data.customer_id identifies the buyer. Fetch their email from the Paddle API
      // (GET /customers/{id}) or read it from data.custom_data if you pass it at checkout.
      console.log('Grant Pro', payload.event_type, data.customer_id, data.id);
      break;
    case 'subscription.canceled':
      // TODO: remove Pro when the paid period ends (data.scheduled_change / data.canceled_at).
      console.log('Subscription canceled', data.customer_id, data.id);
      break;
    default:
      break;
  }

  return { statusCode: 200, body: 'ok' };
};

# Fake Famous landing page

Single-file landing page. `index.html` is generated: edit `index.src.html`, then run `python3 build.py`. The hero video and poster are served from `assets/`.

Paddle: set `CONFIG.paddle.token` and the two price IDs in `index.src.html`, with no trial period on either price. `netlify/functions/paddle-webhook.js` verifies webhook signatures (env `PADDLE_WEBHOOK_SECRET`) and only runs on Netlify.

## Paid-only app (server)

The site runs as a Node web service (`server.js`, no dependencies, `npm start`). The landing and legal pages are public; `/app/` is only served to signed-in buyers with an active Paddle subscription. Sign-in is a 6-digit email code (`/login`), sent through Resend. Sessions last 30 days and are re-checked against Paddle every 6 hours, so cancelled subscriptions lose access once their paid period ends. `/logout` signs out.

Environment variables: `PADDLE_API_KEY`, `PADDLE_ENV` (`sandbox`/`production`, match the landing CONFIG), `RESEND_API_KEY`, `MAIL_FROM`, `SESSION_SECRET`, optional `ALLOW_EMAILS` (comma-separated emails that always get in).

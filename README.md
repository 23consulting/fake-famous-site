# Fake Famous landing page

Single-file landing page. `index.html` is generated: edit `index.src.html`, then run `python3 build.py` (embeds the hero video and poster from `assets/`).

Paddle: set `CONFIG.paddle.token` and the two price IDs in `index.src.html`, with a 3-day trial on both prices. `netlify/functions/paddle-webhook.js` verifies webhook signatures (env `PADDLE_WEBHOOK_SECRET`) and only runs on Netlify.

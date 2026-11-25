# Fake Famous landing page

Single-file landing page. `index.html` is generated: edit `index.src.html`, then run `python3 build.py`. The hero video and poster are served from `assets/`.

Paddle: set `CONFIG.paddle.token` and the two price IDs in `index.src.html`, with no trial period on either price. `netlify/functions/paddle-webhook.js` verifies webhook signatures (env `PADDLE_WEBHOOK_SECRET`) and only runs on Netlify.

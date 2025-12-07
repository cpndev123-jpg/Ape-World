// server.js
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const WebSocket = require('ws');

const SECRET = process.env.WEBHOOK_SECRET; // set this in env
const app = express();

// keep raw body for signature verification
app.use(bodyParser.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));

const wss = new WebSocket.Server({ port: 8081 });

function verifySignature(rawBody, signature) {
  const hmac = crypto.createHmac('sha256', SECRET);
  const digest = 'sha256=' + hmac.update(rawBody).digest('hex');
  try {
    return signature && crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature));
  } catch (e) {
    return false;
  }
}

app.post('/github-webhook', (req, res) => {
  const sig = req.headers['x-hub-signature-256'];
  if (!verifySignature(req.rawBody, sig)) return res.status(401).send('invalid signature');

  const changed = [];
  if (req.body.commits && Array.isArray(req.body.commits)) {
    req.body.commits.forEach(c => {
      (c.added || []).forEach(p => changed.push(p));
      (c.modified || []).forEach(p => changed.push(p));
      (c.removed || []).forEach(p => changed.push(p));
    });
  }

  const payload = {
    type: 'repo_updated',
    repo: req.body.repository.full_name,
    ref: req.body.ref,
    changed: Array.from(new Set(changed))
  };

  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(payload));
  });

  res.status(200).send('ok');
});

app.listen(3000, () => console.log('Webhook server listening on :3000'));

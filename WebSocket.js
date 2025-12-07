// webhook-server.js
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const WebSocket = require('ws');

const SECRET = process.env.WEBHOOK_SECRET || 'replace_me';
const app = express();
app.use(bodyParser.json());

const wss = new WebSocket.Server({ port: 8081 });

function verifySignature(reqBody, signature) {
  const hmac = crypto.createHmac('sha256', SECRET);
  const digest = 'sha256=' + hmac.update(JSON.stringify(reqBody)).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature || ''));
}

app.post('/github-webhook', (req, res) => {
  const sig = req.headers['x-hub-signature-256'];
  if (!verifySignature(req.body, sig)) return res.status(401).send('invalid signature');

  const payload = {
    type: 'repo_updated',
    repo: req.body.repository.full_name,
    ref: req.body.ref,
    commits: req.body.commits?.map(c => c.id) || []
  };

  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(payload));
  });

  res.status(200).send('ok');
});

app.listen(3000, () => console.log('Webhook server listening on :3000'));
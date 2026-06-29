import cors from 'cors';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 5000;

// Flexible CORS for deployment
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || true, 
  credentials: true
}));
app.use(express.json());

// Serve the SDK and Dashboard statically
app.use('/sdk', express.static(path.join(__dirname, '../sdk')));
app.use('/', express.static(path.join(__dirname, '../dashboard')));

// Store clients for Server-Sent Events (SSE)
let clients = [];
// Store recent events for initial load
const recentEvents = [];

// SSE Endpoint for real-time dashboard updates
app.get('/api/events/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  // Send initial history
  res.write(`data: ${JSON.stringify({ type: 'history', data: recentEvents })}\n\n`);

  clients.push(res);

  req.on('close', () => {
    clients = clients.filter(client => client !== res);
  });
});

// Bot Detection Engine
function analyzeBehavior(payload) {
  if (payload.type !== 'behavior_batch') return null;
  
  const clicks = payload.events.filter(e => e.type === 'click');
  const moves = payload.events.filter(e => e.type === 'mousemove');

  // Rule 1: Click Spamming (Brute force or scripted automation)
  if (clicks.length >= 8) {
    return {
      reason: 'BOT_BEHAVIOR_DETECTED',
      details: `Click Spamming: ${clicks.length} rapid clicks detected.`,
      confidence: 'High (95%)'
    };
  }

  // Rule 2: Scripted Click (Clicking without moving mouse)
  // Bots often use element.click() in JS, which bypasses mouse movement
  if (clicks.length > 0 && moves.length === 0) {
    return {
      reason: 'BOT_BEHAVIOR_DETECTED',
      details: 'Non-human interaction: Click occurred with zero mouse trajectory.',
      confidence: 'Medium (80%)'
    };
  }

  return null;
}

// Ingestion API
app.post('/api/ingest', (req, res) => {
  const payload = req.body;
  
  // 1. Keep last 100 events
  recentEvents.unshift(payload);
  if (recentEvents.length > 100) recentEvents.pop();

  // 2. Broadcast normal event
  clients.forEach(client => {
    client.write(`data: ${JSON.stringify({ type: 'new_event', data: payload })}\n\n`);
  });

  // 3. Run Threat Detection Engine
  if (payload.type === 'behavior_batch') {
    const threat = analyzeBehavior(payload);
    
    if (threat) {
      const alertPayload = {
        type: 'SECURITY_ALERT',
        sessionId: payload.sessionId,
        data: threat,
        timestamp: Date.now()
      };
      
      // Store and broadcast the alert
      recentEvents.unshift(alertPayload);
      clients.forEach(client => {
        client.write(`data: ${JSON.stringify({ type: 'new_event', data: alertPayload })}\n\n`);
      });
      console.log(`\n🚨 MAYASEC THREAT ENGINE: Bot Detected -> ${threat.details}`);
    }
  }

  res.status(200).json({ success: true });
});

const server = app.listen(port, () => {
  console.log(`MayaSec backend listening on http://localhost:${port}`);
});

export { app, server };

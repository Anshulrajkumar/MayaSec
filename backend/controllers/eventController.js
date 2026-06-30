import { eventPipeline } from '../engines/eventPipeline.js';
import { eventStore } from '../events/eventStore.js';
import { broadcastService } from '../dashboard/broadcastService.js';
import { getStoredUserByApiKey, getStoredUserById } from '../services/authService.js';
import { siteRegistryService } from '../services/siteRegistryService.js';

function siteFromRequest(req, payloadOrigin) {
  const rawOrigin = req.headers.origin || req.headers.referer || payloadOrigin || 'Unknown';
  if (rawOrigin === 'Unknown') return { origin: rawOrigin, siteName: rawOrigin, hostname: rawOrigin };

  try {
    const parsed = new URL(rawOrigin);
    return {
      origin: parsed.origin,
      siteName: parsed.host.toLowerCase(),
      hostname: parsed.hostname.toLowerCase()
    };
  } catch {
    const siteName = String(rawOrigin).replace(/^https?:\/\//, '').replace(/\/$/, '').toLowerCase();
    return { origin: rawOrigin, siteName, hostname: siteName.replace(/:\d+$/, '') };
  }
}

function isAllowedDomain(hostname, allowedDomain) {
  return hostname === allowedDomain || hostname.endsWith(`.${allowedDomain}`);
}

function setIngestCors(req, res) {
  res.set({
    'Access-Control-Allow-Origin': req.headers.origin || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true'
  });
}

export function ingestOptions(req, res) {
  setIngestCors(req, res);
  res.status(204).end();
}

const ipBlacklist = new Map();

export function checkStatus(req, res) {
  setIngestCors(req, res);
  const clientIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || 'Unknown';
  if (ipBlacklist.has(clientIp)) {
    const expiry = ipBlacklist.get(clientIp);
    if (Date.now() < expiry) {
      return res.status(403).json({ action: 'TIMEOUT', duration: expiry - Date.now() });
    } else {
      ipBlacklist.delete(clientIp);
    }
  }
  res.status(200).json({ ok: true });
}

export async function ingestEvents(req, res) {
  setIngestCors(req, res);

  const clientIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket?.remoteAddress
    || 'Unknown';

  if (ipBlacklist.has(clientIp)) {
    const expiry = ipBlacklist.get(clientIp);
    if (Date.now() < expiry) {
      return res.status(403).json({ action: 'TIMEOUT', duration: expiry - Date.now() });
    } else {
      ipBlacklist.delete(clientIp);
    }
  }

  const payload = req.body;
  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ error: 'Invalid event payload' });
  }

  const apiKey = payload.apiKey;
  if (!apiKey) return res.status(401).json({ error: 'Missing API key' });

  const events = Array.isArray(payload.events) ? payload.events : [payload];
  const { origin, hostname } = siteFromRequest(req, payload.origin);

  let userRecord;
  try {
    userRecord = await getStoredUserByApiKey(apiKey);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }

  if (!userRecord) {
    return res.status(403).json({ error: 'Invalid API key' });
  }

  if (userRecord.allowedDomains.length > 0) {
    const isAllowed = userRecord.allowedDomains.some((domain) => isAllowedDomain(hostname, domain));
    if (!isAllowed) {
      return res.status(403).json({ error: 'Domain not authorized for this API key' });
    }
  }

  const result = eventPipeline.processBatch(events, {
    hostname,
    origin,
    apiKey,
    clientIp,
    websiteId: payload.websiteId || hostname
  });

  const responsePayload = {
    success: true,
    processed: result.normalizedEvents.length,
    derived: result.derivedEvents.length
  };

  if (result.isCritical) {
    let duration = 300000; // 5 minutes default
    
    const hasRapidClicking = result.derivedEvents.some(e => e.metadata?.ruleId === 'rapid-clicking');
    if (hasRapidClicking) {
      duration = 120000; // 2 minutes
    }

    ipBlacklist.set(clientIp, Date.now() + duration);
    responsePayload.action = 'TIMEOUT';
    responsePayload.duration = duration;
  }

  res.status(200).json(responsePayload);
}

export async function streamEvents(req, res) {
  let userRecord;

  try {
    userRecord = await getStoredUserById(req.authUser.id);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }

  if (!userRecord?.apiKey) return res.status(404).json({ error: 'User not registered' });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const history = eventStore.getByApiKey(userRecord.apiKey);
  res.write(`data: ${JSON.stringify({ type: 'history', data: history })}\n\n`);

  broadcastService.addClient(res, userRecord.apiKey);
  req.on('close', () => {
    broadcastService.removeClient(res);
  });
}

export async function getSites(req, res) {
  try {
    const userRecord = await getStoredUserById(req.authUser.id);
    if (!userRecord?.apiKey) return res.status(404).json({ error: 'User not registered' });

    res.json(siteRegistryService.listByApiKey(userRecord.apiKey));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}

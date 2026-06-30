import { eventStore } from '../events/eventStore.js';
import { getStoredUserById } from '../services/authService.js';
import { generateSessionSummary } from '../services/groqService.js';

/**
 * POST /api/ai/session-summary
 * Body: { sessionId?: string, ip?: string }
 * Returns AI-generated analysis of the session/IP events.
 */
export async function sessionSummary(req, res) {
  const { sessionId, ip } = req.body || {};
  if (!sessionId && !ip) {
    return res.status(400).json({ error: 'Provide a sessionId or ip' });
  }

  let userRecord;
  try {
    userRecord = await getStoredUserById(req.authUser.id);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
  if (!userRecord?.apiKey) return res.status(404).json({ error: 'User not registered' });

  // Get all events for this user's API key
  const allEvents = eventStore.getByApiKey(userRecord.apiKey);

  // Filter by sessionId or IP
  let filtered;
  if (sessionId) {
    filtered = allEvents.filter(e => e.sessionId === sessionId);
  } else {
    filtered = allEvents.filter(e => e.ip === ip);
  }

  if (filtered.length === 0) {
    return res.json({ summary: 'No events found for this target.', eventCount: 0 });
  }

  // Sort chronologically
  filtered.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  try {
    const summary = await generateSessionSummary(filtered, {
      ip: ip || filtered[0]?.ip,
      sessionId: sessionId || filtered[0]?.sessionId,
      origin: filtered[0]?.origin
    });

    res.json({ summary, eventCount: filtered.length });
  } catch (error) {
    console.error('[AI] Summary generation failed:', error.message);
    res.status(502).json({ error: 'AI analysis temporarily unavailable. Try again.' });
  }
}

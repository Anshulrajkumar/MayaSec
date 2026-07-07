/**
 * Groq AI service for MayaSec session analysis.
 * Uses round-robin key rotation for rate-limit resilience.
 */

const GROQ_KEYS = [
  process.env.Groq_api_key_1,
  process.env.Groq_api_key_2
].filter(Boolean);

let keyIndex = 0;

function getNextKey() {
  if (GROQ_KEYS.length === 0) throw new Error('No Groq API keys configured');
  const key = GROQ_KEYS[keyIndex % GROQ_KEYS.length];
  keyIndex++;
  return key;
}

const SYSTEM_PROMPT = `You are MayaSec AI — a cybersecurity analyst assistant embedded in a real-time browser security monitoring dashboard.

You receive a batch of raw security telemetry events from a single user session or IP address. Your job is to produce a concise, actionable intelligence summary for a human security analyst.

Your summary MUST include:
1. **Visitor Profile** — One line: who this visitor appears to be (bot, real user, scraper, attacker, etc.)
2. **Behavioral Summary** — 2-3 sentences describing what the visitor did in chronological order.
3. **Risk Indicators** — Bullet list of any suspicious signals detected (or "None detected" if clean).
4. **Verdict** — One of: CLEAN, SUSPICIOUS, MALICIOUS, BOT
5. **Confidence** — A percentage (0-100%)
6. **Recommended Action** — One of: Monitor, Challenge, Block, Escalate, No Action Needed

Keep it under 200 words total. Be direct. No filler. Write like a SOC analyst, not a chatbot.`;

/**
 * Calls the Groq API with automatic key rotation and retry.
 */
async function callGroq(messages, retries = GROQ_KEYS.length) {
  for (let attempt = 0; attempt < retries; attempt++) {
    const apiKey = getNextKey();
    try {
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: 'llama-3.1-8b-instant',
          messages,
          temperature: 0.3,
          max_tokens: 512,
          stream: false
        })
      });

      if (response.status === 429) {
        console.warn(`[Groq] Key ${attempt + 1} rate-limited, rotating...`);
        continue;
      }

      if (!response.ok) {
        const err = await response.text();
        console.error(`[Groq] API error (${response.status}):`, err);
        continue;
      }

      const data = await response.json();
      return data.choices?.[0]?.message?.content || 'No analysis generated.';
    } catch (error) {
      console.error(`[Groq] Request failed (attempt ${attempt + 1}):`, error.message);
    }
  }
  throw new Error('All Groq API keys exhausted or failed');
}

/**
 * Summarizes events into a compact representation for the LLM.
 */
function compactEvents(events) {
  return events.slice(0, 60).map(e => {
    const time = e.timestamp 
      ? new Date(e.timestamp).toLocaleTimeString('en-US', { timeZone: 'Asia/Kolkata' }) 
      : '?';
    const meta = e.metadata || e.data || {};

    // Strip sensitive/noisy fields
    const cleanMeta = { ...meta };
    delete cleanMeta.fingerprint;
    delete cleanMeta.session;
    delete cleanMeta.sourceMetadata;

    const metaStr = Object.entries(cleanMeta)
      .filter(([, v]) => v !== undefined && v !== null && v !== '')
      .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
      .join(', ');

    return `[${time}] ${e.event || e.type} (${e.severity || 'LOW'})${metaStr ? ` — ${metaStr}` : ''}`;
  }).join('\n');
}

/**
 * Generates an AI summary for a set of events.
 * @param {Array} events - Normalized event objects
 * @param {{ ip?: string, sessionId?: string, origin?: string }} context
 * @returns {Promise<string>} The AI-generated summary
 */
export async function generateSessionSummary(events, context = {}) {
  if (!events || events.length === 0) {
    return 'No events available for analysis.';
  }

  const compacted = compactEvents(events);
  const contextLine = [
    context.ip && `IP: ${context.ip}`,
    context.sessionId && `Session: ${context.sessionId}`,
    context.origin && `Site: ${context.origin}`
  ].filter(Boolean).join(' | ');

  const userMessage = `Analyze these ${events.length} security events${contextLine ? ` (${contextLine})` : ''}:\n\n${compacted}`;

  return callGroq([
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'user', content: userMessage }
  ]);
}

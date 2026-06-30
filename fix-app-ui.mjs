import { readFileSync, writeFileSync } from 'fs';

const file = 'dashboard/app-ui.js';
let content = readFileSync(file, 'utf8');

// Find the corrupted part
const corruptedStart = `        tr.innerHTML = \`\r
            <td class="mono">\${time}</td>\r
            document.getElementById('row-action-menu').classList.add('hidden');`;

const index = content.indexOf(`        tr.innerHTML = \`\n            <td class="mono">\${time}</td>\n            document.getElementById('row-action-menu').classList.add('hidden');`) 
  !== -1 ? content.indexOf(`        tr.innerHTML = \`\n            <td class="mono">\${time}</td>\n            document.getElementById('row-action-menu').classList.add('hidden');`) 
  : content.indexOf(`        tr.innerHTML = \`\r\n            <td class="mono">\${time}</td>\r\n            document.getElementById('row-action-menu').classList.add('hidden');`);

if (index !== -1) {
  // we found the bad part. Let's just slice everything from there and replace with the correct ending.
  const goodContent = content.slice(0, index) + `        tr.innerHTML = \`
            <td class="mono">\${time}</td>
            <td><span class="badge badge-info">\${escapeHtml(typeName)}</span></td>
            <td class="mono clickable trace-link" onclick="enterTraceMode('\${escapeHtml(p.sessionId || '')}'); event.stopPropagation();">\${escapeHtml(p.sessionId || '--')}</td>
            <td><span class="badge \${sevClass}">\${sev}</span></td>
            <td style="font-size:0.8rem">\${escapeHtml(summaryFor(p))}</td>
        \`;
        tbody.appendChild(tr);
    });
}

// ===== AI SESSION SUMMARY =====
async function requestAiSummary(mode) {
    const body = {};
    let cardId, bodyId, btn;

    if (mode === 'ip' && selectedUserIp) {
        body.ip = selectedUserIp;
        cardId = 'ai-summary-card';
        bodyId = 'ai-summary-body';
        btn = document.getElementById('btn-ai-summary-ip');
    } else if (mode === 'session' && traceSessionId) {
        body.sessionId = traceSessionId;
        cardId = 'ai-summary-card-trace';
        bodyId = 'ai-summary-body-trace';
        btn = document.querySelector('.ai-summary-btn-trace');
    } else {
        alert('No target selected for AI analysis.');
        return;
    }

    const card = document.getElementById(cardId);
    const summaryBody = document.getElementById(bodyId);

    // Show loading state
    card.classList.remove('hidden');
    summaryBody.innerHTML = \`<div class="ai-loading"><div class="ai-loading-dots"><span></span><span></span><span></span></div><span>Analyzing \${body.ip ? body.ip : 'session'}...</span></div>\`;
    if (btn) { btn.disabled = true; btn.textContent = 'Analyzing...'; }

    try {
        const res = await fetch('/api/ai/session-summary', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify(body)
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || \`Request failed (\${res.status})\`);
        }

        const data = await res.json();
        summaryBody.innerHTML = renderAiMarkdown(data.summary, data.eventCount);
    } catch (error) {
        summaryBody.innerHTML = \`<div class="ai-error">⚠ \${escapeHtml(error.message)}</div>\`;
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = \`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a4 4 0 014 4v1a3 3 0 013 3v1a2 2 0 012 2v4a6 6 0 01-6 6h-6a6 6 0 01-6-6v-4a2 2 0 012-2v-1a3 3 0 013-3V6a4 4 0 014-4z"/><circle cx="9" cy="14" r="1"/><circle cx="15" cy="14" r="1"/></svg> \${mode === 'session' ? 'AI' : 'AI Summary'}\`;
        }
    }
}

function renderAiMarkdown(text, eventCount) {
    if (!text) return '<div class="ai-error">No analysis generated.</div>';

    // Simple markdown → HTML
    let html = escapeHtml(text)
        .replace(/\\*\\*(.+?)\\*\\*/g, '<strong>$1</strong>')
        .replace(/\\*(.+?)\\*/g, '<em>$1</em>')
        .replace(/^- (.+)$/gm, '<li>$1</li>')
        .replace(/(<li>.*<\\/li>)/s, '<ul>$1</ul>')
        .replace(/\\n{2,}/g, '</p><p>')
        .replace(/\\n/g, '<br>');

    html = \`<p>\${html}</p>\`;
    
    // Highlight verdict keywords
    html = html.replace(/(CLEAN|No Action Needed)/g, '<span class="ai-verdict ai-verdict-clean">$1</span>');
    html = html.replace(/(SUSPICIOUS|Challenge|Monitor)/g, '<span class="ai-verdict ai-verdict-suspicious">$1</span>');
    html = html.replace(/(MALICIOUS|BOT|Block|Escalate)/g, '<span class="ai-verdict ai-verdict-danger">$1</span>');

    return \`<div class="ai-content">\${html}</div><div class="ai-footer">\${eventCount} events analyzed</div>\`;
}
`;

  writeFileSync(file, goodContent, 'utf8');
  console.log('Fixed app-ui.js duplicate block issue');
} else {
  console.log('Could not find index to slice');
}

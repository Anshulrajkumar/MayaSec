let savedNotes = JSON.parse(localStorage.getItem('mayasec_notes') || '[]');
let unreadAlerts = JSON.parse(localStorage.getItem('mayasec_unread') || '[]');
let savedAnalystSessions = JSON.parse(localStorage.getItem('mayasec_sessions') || '[]');
let currentAnalystSession = null;
let analystSessionInterval = null;

// ===== NAV =====
function hideAllContent() {
    ['content-dashboard','content-trace','content-summary','content-notes','content-history','content-users'].forEach(id => {
        document.getElementById(id)?.classList.add('hidden');
    });
    document.getElementById('trace-bar')?.classList.add('hidden');
    document.getElementById('investigation-panel')?.classList.add('hidden');
}

function switchNav(nav) {
    document.querySelectorAll('.nav-item[data-nav]').forEach(el => el.classList.toggle('active', el.dataset.nav === nav));
    
    if (nav === 'dashboard' || nav === 'events') {
        exitTraceMode();
        document.getElementById('page-title').textContent = nav === 'dashboard' ? 'Dashboard' : 'Event Stream';
        document.getElementById('page-subtitle').textContent = nav === 'dashboard' ? 'Real-time security monitoring overview' : 'All incoming events';
        document.getElementById('content-notes').classList.add('hidden');
        document.getElementById('content-history').classList.add('hidden');
        document.getElementById('content-users').classList.add('hidden');
    } else if (nav === 'users') {
        currentView = 'users';
        hideAllContent();
        document.getElementById('content-users').classList.remove('hidden');
        document.getElementById('page-title').textContent = 'Active Users';
        document.getElementById('page-subtitle').textContent = 'Monitor connected IPs and their activity in real-time';
        renderUsersView();
    } else if (nav === 'notes') {
        currentView = 'notes';
        hideAllContent();
        document.getElementById('content-notes').classList.remove('hidden');
        document.getElementById('page-title').textContent = 'Analyst Notes';
        document.getElementById('page-subtitle').textContent = 'Review your saved investigation notes and flags';
    } else if (nav === 'history') {
        currentView = 'history';
        hideAllContent();
        document.getElementById('content-history').classList.remove('hidden');
        document.getElementById('page-title').textContent = 'Analysis History';
        document.getElementById('page-subtitle').textContent = 'Review your past recording sessions';
    } else if (nav === 'trace') {
        currentView = 'trace';
        hideAllContent();
        document.getElementById('trace-bar').classList.remove('hidden');
        document.getElementById('content-trace').classList.remove('hidden');
        document.getElementById('page-title').textContent = 'Trace User Activity Mode';
        document.getElementById('page-subtitle').textContent = 'Search or view detailed timeline for a session';
        renderTraceTimeline();
    }
}

// ===== RENDERING =====
function severityFor(p) {
    if (p.severity) return String(p.severity).toLowerCase();
    if (p.type === 'SECURITY_ALERT') return 'high';
    if (p.type === 'behavior_batch') return 'medium';
    return 'low';
}

function summaryFor(p) {
    if (p.type === 'session_start') return `Browser: ${p.data?.fingerprint?.browser?.name||p.data?.browser?.name||'N/A'} | OS: ${p.data?.fingerprint?.device?.platform||p.data?.device?.platform||'N/A'}`;
    if (p.type === 'behavior_batch') return `${p.events?.length||0} user actions recorded`;
    if (p.type === 'SECURITY_ALERT') return p.data?.details || p.data?.reason || 'Security Alert';
    if (p.type === 'login_attempt') return 'User attempted login';
    if (p.type === 'LOGIN_SUCCESS') return 'User submitted login form';
    if (p.type === 'LOGIN_FAILED') return p.data?.reason || 'Login failed';
    if (p.type === 'SQL_INJECTION') return p.data?.formAction ? `Blocked at ${p.data.formAction}` : 'SQL injection attempt blocked';
    if (p.type === 'CLICK_ACTIVITY') return `Click at (${p.data?.x ?? '-'}, ${p.data?.y ?? '-'})`;
    if (p.type === 'MOUSE_ACTIVITY') return `Mouse move at (${p.data?.x ?? '-'}, ${p.data?.y ?? '-'})`;
    if (p.type === 'SCROLL_ACTIVITY') return `Scroll (${p.data?.scrollX ?? 0}, ${p.data?.scrollY ?? 0})`;
    if (p.type === 'KEYBOARD_ACTIVITY') {
        const cat = p.data?.keyCategory || 'key';
        const sensitive = p.data?.sensitiveField ? ' (sensitive field)' : '';
        const count = p.data?.totalKeystrokes || '';
        return `${cat} input #${count}${sensitive}`;
    }
    if (p.type === 'API_REQUEST') return `${p.data?.method || 'GET'} ${p.data?.url || ''}`.trim();
    if (p.type === 'API_RESPONSE') return `${p.data?.status || ''} ${p.data?.url || ''}`.trim();
    if (p.type === 'API_ERROR') return p.data?.error?.message || 'API request failed';
    if (p.type === 'DEVTOOLS_OPENED') return 'Developer tools opened';
    if (p.type === 'DOM_MUTATION') return `${p.data?.mutationCount || 0} DOM mutations detected`;
    if (p.type === 'SCRIPT_INJECTION') return 'Suspicious script injection detected';
    return String(p.type||'').replace(/_/g,' ');
}

function makeRow(p, animate) {
    if (p.type === 'session_start' || p.type === 'session_end' || p.type === 'analyst_session_start' || p.type === 'analyst_session_end') {
        const tr = document.createElement('tr');
        if (animate) tr.className = 'new-row';
        const time = p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : '--';
        const isStart = p.type.includes('start');
        const isAnalyst = p.type.includes('analyst');
        const msg = isAnalyst 
            ? (isStart ? `${escapeHtml(p.data?.name||'')} started` : `${escapeHtml(p.data?.name||'')} ended`)
            : (isStart ? 'USER SESSION STARTED' : 'USER SESSION ENDED');
        const color = isStart ? 'var(--accent)' : 'var(--text-dim)';
        
        tr.innerHTML = `
            <td colspan="7" style="padding:0; border:none; background:transparent;">
                <div style="display:flex; align-items:center; width:100%; padding:16px 0;">
                    <div style="flex:1; height:1px; background:linear-gradient(90deg, transparent, ${color}); opacity:0.3;"></div>
                    <div style="padding:4px 16px; border:1px solid ${color}; border-radius:12px; font-size:0.7rem; font-weight:700; color:${color}; letter-spacing:0.05em; background:var(--surface); display:flex; gap:8px; align-items:center; text-transform:uppercase; white-space:nowrap;">
                        <span class="mono" style="opacity:0.7; font-weight:500;">${time}</span>
                        ${msg}
                        <span class="mono" style="opacity:0.7; font-weight:500;">[${escapeHtml(p.sessionId||'--')}]</span>
                    </div>
                    <div style="flex:1; height:1px; background:linear-gradient(90deg, ${color}, transparent); opacity:0.3;"></div>
                </div>
            </td>
        `;
        return tr;
    }

    const tr = document.createElement('tr');
    if (animate) tr.className = 'new-row';
    if (p.type === 'SECURITY_ALERT') tr.classList.add('alert-row');

    const time = p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : '--';
    const sev = severityFor(p);
    const sevClass = sev === 'high' ? 'badge-high' : sev === 'medium' ? 'badge-medium' : 'badge-low';
    const typeName = String(p.type||'unknown').replace(/_/g,' ');
    const location = p.location || 'Unknown';
    const sessionId = p.sessionId || '--';
    
    tr.innerHTML = `<td class="mono">${time}</td>
        <td><span class="badge badge-info">${escapeHtml(typeName)}</span></td>
        <td class="mono ${sessionId !== '--' ? 'clickable trace-link' : ''}" ${sessionId !== '--' ? `onclick="enterTraceMode('${escapeHtml(sessionId)}'); event.stopPropagation();"` : ''}>${escapeHtml(sessionId)}</td>
        <td style="font-size:0.75rem;color:var(--text-dim)">${escapeHtml(location)}</td>
        <td><span class="badge ${sevClass}">${sev}</span></td>
        <td style="font-size:0.8rem">${escapeHtml(summaryFor(p))}</td>
        <td style="text-align:right; padding-right:1rem;"></td>`;
        
    const btnContainer = tr.lastElementChild;
    const btn = document.createElement('button');
    btn.style.cssText = 'padding:6px; min-height:0; display:inline-flex; align-items:center; justify-content:center; border:none; background:transparent; color:var(--text-dim); cursor:pointer; border-radius:4px;';
    btn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg>`;
    
    btn.onmouseover = () => btn.style.background = 'var(--surface-hover)';
    btn.onmouseout = () => btn.style.background = 'transparent';
    
    btn.onclick = (e) => openRowMenu(e, p);
    btnContainer.appendChild(btn);

    return tr;
}

function renderTable() {
    const tbody = document.getElementById('events-body');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    const typeFilter = document.getElementById('filter-type')?.value || 'all';
    const sevFilter = document.getElementById('filter-severity')?.value || 'all';
    
    const filtered = allEvents.filter(p => {
        if (p.type === 'analyst_session_start' || p.type === 'analyst_session_end') return true;
        if (currentFilter !== 'all' && p.origin !== currentFilter) return false;
        if (typeFilter !== 'all' && p.type !== typeFilter) return false;
        if (sevFilter !== 'all' && severityFor(p) !== sevFilter) return false;
        return true;
    });
    
    filtered.slice(0, 50).forEach(p => tbody.appendChild(makeRow(p, false)));
}

function addEvent(p, animate) {
    allEvents.unshift(p);
    if (allEvents.length > 200) allEvents.pop();
    if (p.sessionId) { uniqueSessions.add(p.sessionId); const s=p.origin||'Unknown'; if(!siteSessionMap[s])siteSessionMap[s]=new Set(); siteSessionMap[s].add(p.sessionId); }
    if (p.type === 'SECURITY_ALERT') { 
        alertCount++; 
        const s=p.origin||'Unknown'; 
        siteAlertMap[s]=(siteAlertMap[s]||0)+1; 
        
        // Prevent duplicates on refresh and respect cleared notifications
        const clearedTimestamp = Number(localStorage.getItem('mayasec_cleared_timestamp') || '0');
        if (p.timestamp > clearedTimestamp) {
            const isDuplicate = unreadAlerts.some(u => u.sessionId === p.sessionId && u.timestamp === p.timestamp);
            if (!isDuplicate) {
                unreadAlerts.push(p);
                localStorage.setItem('mayasec_unread', JSON.stringify(unreadAlerts));
            }
        }
    }
    if (currentAnalystSession) {
        currentAnalystSession.eventsCount++;
        if (p.type === 'SECURITY_ALERT') currentAnalystSession.alertsCount++;
    }

    const typeFilter = document.getElementById('filter-type')?.value || 'all';
    const sevFilter = document.getElementById('filter-severity')?.value || 'all';

    const isAnalystMarker = p.type === 'analyst_session_start' || p.type === 'analyst_session_end';
    const matchesSite = currentFilter === 'all' || p.origin === currentFilter || isAnalystMarker;
    const matchesType = typeFilter === 'all' || p.type === typeFilter || isAnalystMarker;
    const matchesSev = sevFilter === 'all' || severityFor(p) === sevFilter || isAnalystMarker;

    if (matchesSite && matchesType && matchesSev) {
        const tbody = document.getElementById('events-body');
        if (tbody) {
            tbody.insertBefore(makeRow(p, animate), tbody.firstChild);
            if (tbody.children.length > 50) tbody.removeChild(tbody.lastChild);
        }
    }
    updateKPIs();
    if (currentView === 'trace' && traceSessionId && p.sessionId === traceSessionId) renderTraceTimeline();
    if (currentView === 'users') renderUsersView();
}

function updateKPIs() {
    if (currentFilter === 'all') {
        document.getElementById('kpi-sessions').textContent = uniqueSessions.size;
        document.getElementById('kpi-alerts').textContent = alertCount;
    } else {
        document.getElementById('kpi-sessions').textContent = siteSessionMap[currentFilter]?.size || 0;
        document.getElementById('kpi-alerts').textContent = siteAlertMap[currentFilter] || 0;
    }
    const badge = document.getElementById('bell-badge');
    badge.textContent = unreadAlerts.length;
    badge.style.display = unreadAlerts.length > 0 ? 'flex' : 'none';
    
    // TODO: wire blocked IPs to backend
    document.getElementById('kpi-blocked').textContent = 0;
    updateThreatGauge();
}

function updateThreatGauge() {
    // TODO: wire mean threat score to backend
    const currentAlerts = currentFilter === 'all' ? alertCount : (siteAlertMap[currentFilter] || 0);
    const score = Math.min(100, currentAlerts * 15);
    const el = document.getElementById('threat-gauge');
    const color = score === 0 ? 'var(--text-dim)' : score <= 40 ? '#10b981' : score <= 70 ? '#f59e0b' : '#ef4444';
    const level = score === 0 ? 'None' : score <= 40 ? 'Low' : score <= 70 ? 'Medium' : 'High';
    const pct = (score / 100) * 251;
    el.innerHTML = `<svg width="48" height="48"><circle cx="24" cy="24" r="20" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="4"/><circle cx="24" cy="24" r="20" fill="none" stroke="${color}" stroke-width="4" stroke-dasharray="${pct} 251" stroke-linecap="round"/></svg><div class="gauge-label" style="color:${color}">${score}</div>`;
    document.getElementById('threat-level').textContent = level;
    document.getElementById('threat-level').style.color = color;
    document.getElementById('threat-score-text').textContent = `${score}/100`;
}

function updateSiteList(sites) {
    sites.forEach(site => { knownSites.set(site.name, site); });
    updateSiteDropdown();
    updateKPIs();
}

// ===== TRACE MODE =====
function enterTraceMode(sessionId) {
    traceSessionId = sessionId;
    
    const searchInput = document.getElementById('trace-search-input');
    if (searchInput && sessionId) searchInput.value = sessionId;
    
    document.getElementById('trace-session-id').textContent = sessionId || '--';
    
    // Attempt to grab IP from the first matched event, otherwise use mocked
    const evt = allEvents.find(p => p.sessionId === sessionId);
    document.getElementById('trace-ip').textContent = evt?.ip || (sessionId ? '103.21.244.11' : '--');
    document.getElementById('trace-location').textContent = evt?.location || (sessionId ? 'Mumbai, India 🇮🇳' : '--');
    
    // Calculate and update risk badge for this session
    const eventsForSession = allEvents.filter(p => p.sessionId === sessionId);
    let maxRisk = 'LOW';
    let badgeClass = 'badge-trace-low';
    
    if (eventsForSession.some(e => severityFor(e) === 'high')) {
        maxRisk = 'HIGH';
        badgeClass = 'badge-trace-high';
    } else if (eventsForSession.some(e => severityFor(e) === 'medium')) {
        maxRisk = 'MEDIUM';
        badgeClass = 'badge-trace-medium';
    }
    
    const badge = document.getElementById('trace-risk-badge');
    if (badge) {
        badge.textContent = maxRisk;
        badge.className = badgeClass;
    }
    
    switchNav('trace');
}

function exitTraceMode() {
    currentView = 'dashboard';
    traceSessionId = null;
    document.getElementById('trace-bar').classList.add('hidden');
    document.getElementById('content-dashboard').classList.remove('hidden');
    document.getElementById('content-trace').classList.add('hidden');
    document.getElementById('content-summary').classList.add('hidden');
    document.getElementById('content-notes').classList.add('hidden');
    document.getElementById('content-history').classList.add('hidden');
    document.getElementById('investigation-panel').classList.add('hidden');
    document.getElementById('page-title').textContent = 'Dashboard';
    document.getElementById('page-subtitle').textContent = 'Real-time security monitoring overview';
    document.querySelectorAll('.nav-item[data-nav]').forEach(el => el.classList.toggle('active', el.dataset.nav === 'dashboard'));
}

function executeTraceSearch() {
    const input = document.getElementById('trace-search-input');
    if (!input) return;
    const query = input.value.trim().toLowerCase();
    
    if (!query) {
        traceSessionId = null;
        renderTraceTimeline();
        return;
    }

    const matchingSessions = new Set();
    allEvents.forEach(p => {
        if (!p.sessionId) return;
        
        // Use p.ip if present, otherwise assume the mocked IP for the demo
        const ip = p.ip || '103.21.244.11';
        
        if (p.sessionId.toLowerCase().includes(query) || 
            (p.location && p.location.toLowerCase().includes(query)) ||
            (ip && ip.toLowerCase().includes(query)) ||
            (p.data && JSON.stringify(p.data).toLowerCase().includes(query))) {
            matchingSessions.add(p.sessionId);
        }
    });

    if (matchingSessions.size === 0) {
        alert("No activity found matching that query.");
        traceSessionId = null;
        renderTraceTimeline();
        return;
    }

    const mostRecentMatch = allEvents.find(p => matchingSessions.has(p.sessionId));
    if (mostRecentMatch) {
        enterTraceMode(mostRecentMatch.sessionId);
    }
}

function renderTraceTimeline() {
    const tbody = document.getElementById('trace-body');
    const emptyState = document.getElementById('trace-empty-state');
    const tableContainer = document.getElementById('trace-table-container');
    
    if (!tbody || !emptyState || !tableContainer) return;

    if (!traceSessionId) {
        emptyState.style.display = 'block';
        tableContainer.style.display = 'none';
        document.getElementById('trace-session-id').textContent = '--';
        document.getElementById('trace-ip').textContent = '--';
        document.getElementById('trace-location').textContent = '--';
        return;
    }

    emptyState.style.display = 'none';
    tableContainer.style.display = 'block';
    
    tbody.innerHTML = '';
    const events = allEvents.filter(p => p.sessionId === traceSessionId);
    events.forEach(p => {
        // Expand behavior_batch into individual rows
        if (p.type === 'behavior_batch' && Array.isArray(p.events)) {
            p.events.slice().reverse().forEach(evt => {
                const tr = document.createElement('tr');
                const time = p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : '--';
                const icon = evt.type === 'click' ? '🖱' : evt.type === 'mousemove' ? '⊕' : '⚡';
                const label = evt.type === 'click' ? 'Click' : evt.type === 'mousemove' ? 'Mouse Move' : evt.type;
                const details = evt.type === 'click' ? 'Left click' : evt.type === 'mousemove' ? 'Mouse moved' : evt.type;
                const data = evt.x !== undefined ? `Position: (x: ${evt.x}, y: ${evt.y})` : JSON.stringify(evt);
                tr.innerHTML = `<td class="mono">${time}</td><td><span class="event-label"><span class="event-icon">${icon}</span> ${escapeHtml(label)}</span></td><td>${escapeHtml(details)}</td><td class="mono" style="font-size:0.75rem">${escapeHtml(data)}</td><td></td>`;
                tbody.appendChild(tr);
            });
        } else if (p.type === 'SECURITY_ALERT') {
            const tr = document.createElement('tr');
            tr.classList.add('alert-row');
            
            const time = p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : '--';
            const details = p.data?.details || 'Alert detected';
            const confidence = p.data?.confidence || 'N/A';
            tr.innerHTML = `<td class="mono">${time}</td><td><span class="event-label"><span class="event-icon">⚠</span> <span>Security Alert</span></span></td><td>${escapeHtml(details)}</td><td class="mono" style="font-size:0.75rem;">10 rapid clicks in 1.2 sec<br>Confidence: ${escapeHtml(confidence.replace('High (', '').replace(')', ''))}</td><td style="text-align:right;"></td>`;
            
            const btnContainer = tr.lastElementChild;
            const btn = document.createElement('button');
            btn.style.cssText = 'padding:6px; min-height:0; display:inline-flex; align-items:center; justify-content:center; border:none; background:transparent; color:var(--text-dim); cursor:pointer; border-radius:4px;';
            btn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg>`;
            btn.onmouseover = () => btn.style.background = 'var(--surface-hover)';
            btn.onmouseout = () => btn.style.background = 'transparent';
            btn.onclick = (e) => openRowMenu(e, p);
            btnContainer.appendChild(btn);
            
            tbody.appendChild(tr);
        } else if (['CLICK_ACTIVITY', 'MOUSE_ACTIVITY', 'SCROLL_ACTIVITY', 'KEYBOARD_ACTIVITY', 'API_REQUEST', 'API_RESPONSE', 'API_ERROR', 'DEVTOOLS_OPENED', 'DOM_MUTATION', 'SCRIPT_INJECTION', 'SQL_INJECTION', 'LOGIN_ATTEMPT', 'LOGIN_SUCCESS', 'LOGIN_FAILED'].includes(p.type)) {
            const tr = document.createElement('tr');
            const time = p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : '--';
            const label = String(p.type || 'Event').replace(/_/g, ' ');
            tr.innerHTML = `<td class="mono">${time}</td><td><span class="event-label"><span class="event-icon">•</span> ${escapeHtml(label)}</span></td><td>${escapeHtml(summaryFor(p))}</td><td class="mono" style="font-size:0.75rem">${escapeHtml(JSON.stringify(p.data || {}))}</td><td></td>`;
            tbody.appendChild(tr);
        } else if (p.type === 'session_start' || p.type === 'session_end') {
            const tr = document.createElement('tr');
            const time = p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : '--';
            const isStart = p.type === 'session_start';
            const msg = isStart ? 'NEW USER SESSION STARTED' : 'USER SESSION ENDED';
            const color = isStart ? 'var(--accent)' : 'var(--text-dim)';
            
            tr.innerHTML = `
                <td colspan="5" style="padding:0; border:none; background:transparent;">
                    <div style="display:flex; align-items:center; width:100%; padding:16px 0;">
                        <div style="flex:1; height:1px; background:linear-gradient(90deg, transparent, ${color}); opacity:0.3;"></div>
                        <div style="padding:4px 16px; border:1px solid ${color}; border-radius:12px; font-size:0.7rem; font-weight:700; color:${color}; letter-spacing:0.05em; background:var(--surface); display:flex; gap:8px; align-items:center; text-transform:uppercase; white-space:nowrap;">
                            <span class="mono" style="opacity:0.7; font-weight:500;">${time}</span>
                            ${msg}
                        </div>
                        <div style="flex:1; height:1px; background:linear-gradient(90deg, ${color}, transparent); opacity:0.3;"></div>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        }
    });
}

// ===== INVESTIGATION PANEL =====
function openInvestigation(alertData) {
    investigationAlert = alertData;
    traceSessionId = alertData.sessionId;
    selectedFlag = null;
    document.querySelectorAll('.flag-btn').forEach(b => b.classList.remove('selected'));
    document.getElementById('inv-note').value = '';
    document.getElementById('inv-char-count').textContent = '0';
    
    const details = document.getElementById('inv-alert-details');
    let html = `<div class="inv-detail-row"><span class="label">Event Type</span><span>${escapeHtml(String(alertData.type||'Unknown').replace(/_/g,' '))}</span></div>`;
    
    if (alertData.type === 'SECURITY_ALERT') {
        html += `<div class="inv-detail-row"><span class="label">Confidence</span><span>${escapeHtml(alertData.data?.confidence||'N/A')}</span></div>
                 <div class="inv-detail-row"><span class="label">Reason</span><span>${escapeHtml(alertData.data?.reason||'N/A')}</span></div>
                 <div class="inv-detail-row"><span class="label">Details</span><span>${escapeHtml(alertData.data?.details||'N/A')}</span></div>`;
    } else if (alertData.type === 'behavior_batch') {
        html += `<div class="inv-detail-row"><span class="label">Actions Recorded</span><span>${alertData.events?.length||0} events</span></div>`;
    } else if (alertData.type === 'session_start') {
        html += `<div class="inv-detail-row"><span class="label">Browser</span><span>${escapeHtml(alertData.data?.fingerprint?.browser?.name||alertData.data?.browser?.name||'N/A')}</span></div>
                 <div class="inv-detail-row"><span class="label">OS</span><span>${escapeHtml(alertData.data?.fingerprint?.device?.platform||alertData.data?.device?.platform||'N/A')}</span></div>`;
    } else {
        html += `<div class="inv-detail-row"><span class="label">Summary</span><span>${escapeHtml(summaryFor(alertData))}</span></div>`;
    }
    
    html += `<div class="inv-detail-row"><span class="label">Session ID</span><span class="mono">${escapeHtml(alertData.sessionId||'--')}</span></div>`;
    
    details.innerHTML = html;
    document.getElementById('investigation-panel').classList.remove('hidden');
}

function closeInvestigation() { document.getElementById('investigation-panel').classList.add('hidden'); }
function updateCharCount() { document.getElementById('inv-char-count').textContent = document.getElementById('inv-note').value.length; }

function selectFlag(btn, flag) {
    document.querySelectorAll('.flag-btn').forEach(b => b.classList.remove('selected'));
    btn.classList.add('selected');
    selectedFlag = flag;
}

function doAction(action) {
    const note = document.getElementById('inv-note').value;
    if (note.trim() || selectedFlag || action) {
        savedNotes.push({
            time: Date.now(),
            sessionId: traceSessionId || investigationAlert?.sessionId || '--',
            action: action,
            flag: selectedFlag,
            note: note.trim()
        });
        localStorage.setItem('mayasec_notes', JSON.stringify(savedNotes));
        renderNotes();
    }
    closeInvestigation();
    showFinalSummary(action, note);
}

function renderNotes() {
    const tbody = document.getElementById('notes-body');
    if (!tbody) return;
    if (savedNotes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:2rem;">No notes saved yet. Add a note during an investigation to see it here.</td></tr>';
        return;
    }
    tbody.innerHTML = '';
    savedNotes.slice().reverse().forEach((n, i) => {
        const realIndex = savedNotes.length - 1 - i;
        const tr = document.createElement('tr');
        const timeStr = new Date(n.time).toLocaleTimeString();
        let badgeHtml = '';
        if (n.action === 'block') badgeHtml += '<span class="badge badge-high" style="margin-right:4px;">BLOCKED</span>';
        else if (n.action === 'escalate') badgeHtml += '<span class="badge badge-high" style="margin-right:4px;">ESCALATED</span>';
        else if (n.action === 'challenge') badgeHtml += '<span class="badge badge-medium" style="margin-right:4px;">CHALLENGED</span>';
        
        if (n.flag) badgeHtml += `<span class="badge badge-info">${escapeHtml(n.flag)}</span>`;
        
        tr.innerHTML = `
            <td class="mono">${timeStr}</td>
            <td class="mono clickable trace-link" onclick="enterTraceMode('${escapeHtml(n.sessionId)}'); event.stopPropagation(); switchNav('trace');">${escapeHtml(n.sessionId)}</td>
            <td>${badgeHtml || '--'}</td>
            <td>${escapeHtml(n.note) || '<i>No note text provided</i>'}</td>
            <td style="text-align:right;">
                <button class="action-btn" style="padding:4px; color:var(--danger); border:none; background:transparent; cursor:pointer;" onclick="deleteNote(${realIndex})" title="Delete Note">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// ===== FINAL SUMMARY =====
function showFinalSummary(action, note) {
    currentView = 'summary';
    document.getElementById('content-dashboard').classList.add('hidden');
    document.getElementById('content-trace').classList.add('hidden');
    document.getElementById('content-summary').classList.remove('hidden');

    const eventsForSession = allEvents.filter(p => p.sessionId === traceSessionId);
    
    // Calculate Risk Score
    let calculatedScore = 10; // base score
    eventsForSession.forEach(e => {
        if (e.type === 'SECURITY_ALERT') {
            const conf = e.data?.confidence || '';
            if (conf.includes('High')) calculatedScore += 40;
            else calculatedScore += 25;
        }
        if (['CLICK_ACTIVITY', 'MOUSE_ACTIVITY', 'SCROLL_ACTIVITY', 'KEYBOARD_ACTIVITY'].includes(e.type)) {
            calculatedScore += 1;
        }
        if (typeof e.riskScore === 'number') {
            calculatedScore = Math.max(calculatedScore, e.riskScore);
        }
    });
    if (selectedFlag === 'Bot Pattern') calculatedScore += 30;
    if (selectedFlag === 'Credential Stuffing') calculatedScore += 40;
    if (selectedFlag === 'Scraping') calculatedScore += 25;
    if (action === 'block') calculatedScore += 20;
    
    const riskScore = Math.min(100, Math.round(calculatedScore));
    const riskColor = riskScore >= 70 ? '#ef4444' : riskScore >= 40 ? '#f59e0b' : '#10b981';
    const riskLevel = riskScore >= 70 ? 'HIGH RISK' : riskScore >= 40 ? 'MEDIUM RISK' : 'LOW RISK';
    const pct = (riskScore/100)*251;

    document.getElementById('summary-risk-card').innerHTML = `
        <div style="position:relative; display:inline-flex; justify-content:center; align-items:center; width:120px; height:120px; margin:0 auto 1rem auto;">
            <svg width="120" height="120" style="transform: rotate(-90deg);">
                <circle cx="60" cy="60" r="40" fill="none" stroke="var(--border-strong)" stroke-width="8"/>
                <circle cx="60" cy="60" r="40" fill="none" stroke="${riskColor}" stroke-width="8" stroke-dasharray="${pct} 251" stroke-linecap="round"/>
            </svg>
            <div style="position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center;">
                <span style="font-size:2rem; font-weight:800; line-height:1; color:${riskColor};">${riskScore}</span>
                <span style="font-size:0.75rem; color:var(--text-dim); margin-top:2px;">/100</span>
            </div>
        </div>
        <div style="font-size:0.75rem; font-weight:700; letter-spacing:0.05em; color:${riskColor}; margin-bottom:8px;">SESSION RISK SCORE</div>
        <div><span class="badge ${riskScore >= 70 ? 'badge-high' : riskScore >= 40 ? 'badge-medium' : 'badge-low'}">${riskLevel}</span></div>
        <p style="font-size:0.8rem; color:var(--text-dim); margin-top:12px;">Based on ${eventsForSession.length} captured events.</p>
    `;

    // Summary timeline
    const stbody = document.getElementById('summary-timeline-body');
    stbody.innerHTML = '';
    const events = allEvents.filter(p => p.sessionId === traceSessionId).slice().reverse();
    events.forEach(p => {
        const tr = document.createElement('tr');
        if(p.type==='SECURITY_ALERT') tr.classList.add('alert-row');
        const time = p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : '--';
        const typeName = p.type === 'SECURITY_ALERT' ? 'Security Alert' : p.type === 'behavior_batch' ? 'Behavior' : p.type === 'session_start' ? 'Session Start' : String(p.type || 'event').replace(/_/g, ' ');
        const statusIcon = p.type === 'SECURITY_ALERT' ? `<span class="badge badge-high">HIGH</span> ${selectedFlag ? `<span class="badge badge-info">${escapeHtml(selectedFlag)}</span>` : ''}` : '<span class="status-check">✓</span>';
        tr.innerHTML = `<td class="timeline-dot-col"><span class="dot-indicator ${p.type==='SECURITY_ALERT'?'dot-red':'dot-blue'}"></span></td><td class="mono">${time}</td><td>${escapeHtml(typeName)}</td><td style="font-size:0.75rem">${escapeHtml(summaryFor(p))}</td><td>${statusIcon}</td>`;
        stbody.appendChild(tr);
    });

    // Summary info
    document.getElementById('summary-info-card').innerHTML = `<div class="inv-section-title">TRACE SUMMARY</div>
        <div class="summary-meta-row"><span class="lbl">Session ID</span><span class="mono">${escapeHtml(traceSessionId)}</span></div>
        <div class="summary-meta-row"><span class="lbl">IP Address</span><span class="mono">103.21.244.11</span></div>
        <div class="summary-meta-row"><span class="lbl">Location</span><span>Mumbai, India</span></div>
        <div class="summary-meta-row"><span class="lbl">Total Events</span><span>${events.length}</span></div>
        <div class="summary-meta-row"><span class="lbl">Alerts</span><span style="color:var(--danger)">${events.filter(e=>e.type==='SECURITY_ALERT').length}</span></div>
        <div class="inv-section" style="margin-top:1rem"><div class="inv-section-title">ANALYST NOTES</div><p class="summary-notes">${escapeHtml(note||'No notes added.')}</p></div>
        <div class="inv-section"><div class="inv-section-title">CONCLUSION</div><p class="summary-conclusion">Confirmed ${selectedFlag||'suspicious'} behavior on session.</p></div>
        <div class="inv-section"><div class="inv-section-title">ACTIONS TAKEN</div>
            <div class="checklist-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg> Flagged as ${selectedFlag||'Suspicious'}</div>
            <div class="checklist-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg> High Severity</div>
            ${note ? '<div class="checklist-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg> Analyst Note Added</div>' : ''}
            <div class="checklist-item"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg> Session Marked for ${action === 'block' ? 'Blocking' : action === 'escalate' ? 'Escalation' : 'Challenge'}</div>
        </div>`;
}

// ===== NOTIFICATIONS =====
function toggleNotifications() {
    const el = document.getElementById('notification-dropdown');
    el.classList.toggle('hidden');
    if (!el.classList.contains('hidden')) renderNotifications();
}

function renderNotifications() {
    const body = document.getElementById('notif-body');
    if (unreadAlerts.length === 0) {
        body.innerHTML = '<div class="notif-empty">No new alerts.</div>';
        return;
    }
    body.innerHTML = '';
    unreadAlerts.slice().reverse().forEach(p => {
        const div = document.createElement('div');
        div.className = 'notif-item unread';
        div.onclick = () => {
            document.getElementById('notification-dropdown').classList.add('hidden');
            switchNav('dashboard');
            openInvestigation(p);
        };
        const time = p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : '--';
        const title = escapeHtml(p.data?.details || p.data?.reason || 'Security Alert');
        const desc = `Session: ${escapeHtml(p.sessionId||'Unknown')}`;
        div.innerHTML = `<div class="notif-time">${time}</div><div class="notif-title">${title}</div><div class="notif-desc">${desc}</div>`;
        body.appendChild(div);
    });
}

function clearNotifications() {
    unreadAlerts = [];
    localStorage.setItem('mayasec_unread', JSON.stringify(unreadAlerts));
    localStorage.setItem('mayasec_cleared_timestamp', Date.now().toString());
    const badge = document.getElementById('bell-badge');
    badge.textContent = '0';
    badge.style.display = 'none';
    renderNotifications();
}

// ===== ANALYST SESSIONS =====
function openStartSessionModal() { document.getElementById('start-session-modal').classList.remove('hidden'); }
function closeStartSessionModal() { document.getElementById('start-session-modal').classList.add('hidden'); }

function startAnalysisSession() {
    const input = document.getElementById('analyst-session-input');
    const name = input.value.trim() || 'Unnamed Session';
    currentAnalystSession = {
        id: 'as_' + Date.now(),
        name: name,
        startTime: Date.now(),
        endTime: null,
        eventsCount: 0,
        alertsCount: 0
    };
    input.value = '';
    closeStartSessionModal();
    
    document.getElementById('btn-start-session').classList.add('hidden');
    document.getElementById('btn-end-session').classList.remove('hidden');
    document.getElementById('active-analyst-session').style.display = 'flex';
    document.getElementById('analyst-session-name').textContent = escapeHtml(name);
    
    updateSessionTimer();
    analystSessionInterval = setInterval(updateSessionTimer, 1000);
    
    addEvent({
        type: 'analyst_session_start',
        timestamp: Date.now(),
        sessionId: currentAnalystSession.id,
        origin: currentFilter !== 'all' ? currentFilter : 'Unknown',
        data: { name }
    }, true);
}

function updateSessionTimer() {
    if (!currentAnalystSession) return;
    const diff = Math.floor((Date.now() - currentAnalystSession.startTime) / 1000);
    const m = String(Math.floor(diff / 60)).padStart(2, '0');
    const s = String(diff % 60).padStart(2, '0');
    document.getElementById('analyst-session-timer').textContent = `${m}:${s}`;
}

function endAnalysisSession() {
    if (!currentAnalystSession) return;
    clearInterval(analystSessionInterval);
    currentAnalystSession.endTime = Date.now();
    savedAnalystSessions.push(currentAnalystSession);
    localStorage.setItem('mayasec_sessions', JSON.stringify(savedAnalystSessions));
    const endedSessionName = currentAnalystSession.name;
    const endedSessionId = currentAnalystSession.id;
    currentAnalystSession = null;
    
    document.getElementById('btn-start-session').classList.remove('hidden');
    document.getElementById('btn-end-session').classList.add('hidden');
    document.getElementById('active-analyst-session').style.display = 'none';
    
    addEvent({
        type: 'analyst_session_end',
        timestamp: Date.now(),
        sessionId: endedSessionId,
        origin: currentFilter !== 'all' ? currentFilter : 'Unknown',
        data: { name: endedSessionName }
    }, true);
    
    renderHistory();
    switchNav('history');
}

function applyHistoryFilter() {
    const filter = document.getElementById('history-date-filter').value;
    const customDateInput = document.getElementById('history-custom-date');
    if (filter === 'custom') {
        customDateInput.style.display = 'block';
    } else {
        customDateInput.style.display = 'none';
    }
    renderHistory();
}

function renderHistory() {
    const tbody = document.getElementById('history-body');
    if (!tbody) return;
    
    let filteredSessions = savedAnalystSessions.map((s, i) => ({ ...s, originalIndex: i }));
    const filter = document.getElementById('history-date-filter')?.value || 'all';
    
    if (filter !== 'all') {
        const now = new Date();
        const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
        const startOfYesterday = startOfToday - 86400000;
        const startOfLastWeek = startOfToday - (7 * 86400000);
        
        filteredSessions = filteredSessions.filter(s => {
            if (filter === 'today') return s.startTime >= startOfToday;
            if (filter === 'yesterday') return s.startTime >= startOfYesterday && s.startTime < startOfToday;
            if (filter === 'last_week') return s.startTime >= startOfLastWeek;
            if (filter === 'custom') {
                const customDate = document.getElementById('history-custom-date')?.value;
                if (!customDate) return true;
                const [y, m, d] = customDate.split('-').map(Number);
                const customStart = new Date(y, m - 1, d).getTime();
                const customEnd = customStart + 86400000;
                return s.startTime >= customStart && s.startTime < customEnd;
            }
            return true;
        });
    }

    if (filteredSessions.length === 0) {
        if (savedAnalystSessions.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:2rem;">No analysis sessions saved yet. Start a session from the top bar to record history.</td></tr>';
        } else {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:2rem;">No analysis sessions found for the selected date.</td></tr>';
        }
        return;
    }
    
    tbody.innerHTML = '';
    filteredSessions.slice().reverse().forEach((s) => {
        const realIndex = s.originalIndex;
        const tr = document.createElement('tr');
        const durationSecs = Math.floor((s.endTime - s.startTime) / 1000);
        const m = String(Math.floor(durationSecs / 60)).padStart(2, '0');
        const sec = String(durationSecs % 60).padStart(2, '0');
        const timeStr = new Date(s.startTime).toLocaleString();
        
        tr.innerHTML = `
            <td style="font-weight:600; color:var(--text);">${escapeHtml(s.name)}</td>
            <td class="mono">${m}m ${sec}s</td>
            <td class="mono">${s.eventsCount}</td>
            <td class="mono" style="color:${s.alertsCount > 0 ? 'var(--danger)' : 'inherit'}">${s.alertsCount}</td>
            <td class="mono" style="font-size:0.75rem;">${timeStr}</td>
            <td style="text-align:right;">
                <button class="action-btn" style="padding:4px; color:var(--danger); border:none; background:transparent; cursor:pointer;" onclick="deleteHistory(${realIndex})" title="Delete History">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                </button>
            </td>
        `;
        tbody.appendChild(tr);

        const sessionNotes = savedNotes.filter(n => n.time >= s.startTime && n.time <= s.endTime);
        if (sessionNotes.length > 0) {
            const trNotes = document.createElement('tr');
            trNotes.style.backgroundColor = 'var(--bg)';
            
            let notesHtml = '<div style="padding:12px 24px; font-size:0.8rem; border-left: 3px solid var(--primary);">';
            notesHtml += '<div style="font-weight:600; margin-bottom:12px; color:var(--text-dim); text-transform:uppercase; font-size:0.7rem; letter-spacing:0.05em;">Analyst Actions & Notes taken during session:</div>';
            
            sessionNotes.forEach(n => {
                let badgeHtml = '';
                if (n.action === 'block') badgeHtml += '<span class="badge badge-high" style="margin-right:4px;">BLOCKED</span>';
                else if (n.action === 'escalate') badgeHtml += '<span class="badge badge-high" style="margin-right:4px;">ESCALATED</span>';
                else if (n.action === 'challenge') badgeHtml += '<span class="badge badge-medium" style="margin-right:4px;">CHALLENGED</span>';
                if (n.flag) badgeHtml += `<span class="badge badge-info" style="margin-right:4px;">${escapeHtml(n.flag)}</span>`;

                notesHtml += `<div style="margin-bottom:10px; display:flex; gap:16px; align-items:flex-start;">
                    <div class="mono" style="color:var(--text-muted); font-size:0.7rem; padding-top:2px;">${new Date(n.time).toLocaleTimeString()}</div>
                    <div>
                        <div style="margin-bottom:4px; font-size:0.75rem;">${badgeHtml} <span class="mono" style="color:var(--text-dim);">Session: ${escapeHtml(n.sessionId)}</span></div>
                        <div style="color:var(--text); font-style:italic;">"${escapeHtml(n.note) || 'No note text provided'}"</div>
                    </div>
                </div>`;
            });
            notesHtml += '</div>';
            
            trNotes.innerHTML = `<td colspan="5" style="padding:0; border-top:none;">${notesHtml}</td>`;
            tbody.appendChild(trNotes);
        }
    });
}

function deleteNote(index) {
    if (!confirm('Are you sure you want to delete this note?')) return;
    savedNotes.splice(index, 1);
    localStorage.setItem('mayasec_notes', JSON.stringify(savedNotes));
    renderNotes();
}

function deleteHistory(index) {
    if (!confirm('Are you sure you want to delete this session history?')) return;
    savedAnalystSessions.splice(index, 1);
    localStorage.setItem('mayasec_sessions', JSON.stringify(savedAnalystSessions));
    renderHistory();
}

// ===== INIT =====
window.addEventListener('DOMContentLoaded', () => {
    renderNotes();
    renderHistory();
    renderNotifications();
    const badge = document.getElementById('bell-badge');
    if (badge) {
        badge.textContent = unreadAlerts.length;
        badge.style.display = unreadAlerts.length > 0 ? 'flex' : 'none';
    }
    
    // Setup click handlers for the row action menu
    document.getElementById('row-action-investigate')?.addEventListener('click', () => {
        if (activeDropdownEvent) {
            document.getElementById('row-action-menu').classList.add('hidden');
            openInvestigation(activeDropdownEvent);
        }
    });
    
    document.getElementById('row-action-trace')?.addEventListener('click', () => {
        if (activeDropdownEvent && activeDropdownEvent.sessionId) {
            document.getElementById('row-action-menu').classList.add('hidden');
            enterTraceMode(activeDropdownEvent.sessionId);
        } else {
            alert('No Session ID available for this event.');
        }
    });
});

// ===== ROW ACTION MENU =====
let activeDropdownEvent = null;

function openRowMenu(e, p) {
    e.stopPropagation();
    activeDropdownEvent = p;
    const menu = document.getElementById('row-action-menu');
    menu.classList.remove('hidden');
    
    const rect = e.target.closest('button').getBoundingClientRect();
    menu.style.top = `${rect.bottom + 5}px`;
    menu.style.left = `${Math.max(10, rect.right - 180)}px`;
}

document.addEventListener('click', (e) => {
    const menu = document.getElementById('row-action-menu');
    if (menu && !menu.classList.contains('hidden') && !menu.contains(e.target)) {
        menu.classList.add('hidden');
    }
});

// ===== ACTIVE USERS =====
let selectedUserIp = null;

function getIpUserMap() {
    const ipMap = new Map();
    allEvents.forEach(p => {
        const ip = p.ip || 'Unknown';
        if (ip === 'Unknown') return;
        if (!ipMap.has(ip)) {
            ipMap.set(ip, {
                ip,
                sessions: new Set(),
                events: [],
                alerts: 0,
                firstSeen: p.timestamp,
                lastSeen: p.timestamp,
                maxSeverity: 'low',
                riskScore: 0,
                origins: new Set()
            });
        }
        const user = ipMap.get(ip);
        user.events.push(p);
        if (p.sessionId) user.sessions.add(p.sessionId);
        if (p.origin) user.origins.add(p.origin);
        if (p.timestamp < user.firstSeen) user.firstSeen = p.timestamp;
        if (p.timestamp > user.lastSeen) user.lastSeen = p.timestamp;
        if (p.type === 'SECURITY_ALERT') user.alerts++;

        const sev = severityFor(p);
        if (sev === 'high' || user.maxSeverity === 'high') user.maxSeverity = 'high';
        else if (sev === 'medium' && user.maxSeverity !== 'high') user.maxSeverity = 'medium';

        if (typeof p.riskScore === 'number' && p.riskScore > user.riskScore) user.riskScore = p.riskScore;
    });
    return ipMap;
}

function renderUsersView() {
    const grid = document.getElementById('users-grid');
    const detailPanel = document.getElementById('user-detail-panel');
    if (!grid) return;

    const ipMap = getIpUserMap();
    const users = Array.from(ipMap.values()).sort((a, b) => {
        if (b.alerts !== a.alerts) return b.alerts - a.alerts;
        return b.events.length - a.events.length;
    });

    // Update stats
    document.getElementById('users-total-count').textContent = users.length;
    const totalSessions = users.reduce((sum, u) => sum + u.sessions.size, 0);
    document.getElementById('users-total-sessions').textContent = totalSessions;
    const flaggedCount = users.filter(u => u.alerts > 0).length;
    document.getElementById('users-flagged-count').textContent = flaggedCount;

    if (selectedUserIp && ipMap.has(selectedUserIp)) {
        grid.classList.add('hidden');
        detailPanel.classList.remove('hidden');
        renderUserDetail(ipMap.get(selectedUserIp));
        return;
    }

    grid.classList.remove('hidden');
    detailPanel.classList.add('hidden');
    grid.innerHTML = '';

    if (users.length === 0) {
        grid.innerHTML = `<div class="users-empty">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.4; margin-bottom:1rem;"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>
            <p>No user activity detected yet.<br>Interact with a monitored site to see connected IPs here.</p>
        </div>`;
        return;
    }

    users.forEach(user => {
        const card = document.createElement('div');
        card.className = `user-card ${user.alerts > 0 ? 'user-card-flagged' : ''}`;
        card.onclick = () => openUserDetail(user.ip);

        const sevBadge = user.maxSeverity === 'high' ? 'badge-high' : user.maxSeverity === 'medium' ? 'badge-medium' : 'badge-low';
        const riskLevel = user.maxSeverity.toUpperCase();
        const lastSeenStr = user.lastSeen ? new Date(user.lastSeen).toLocaleTimeString() : '--';
        const originList = Array.from(user.origins).join(', ');

        card.innerHTML = `
            <div class="user-card-top">
                <div class="user-card-icon ${user.alerts > 0 ? 'user-card-icon-danger' : ''}">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                </div>
                <div class="user-card-ip-group">
                    <div class="user-card-ip">${escapeHtml(user.ip)}</div>
                    <div class="user-card-origin">${escapeHtml(originList)}</div>
                </div>
                <span class="badge ${sevBadge}" style="margin-left:auto;">${riskLevel}</span>
            </div>
            <div class="user-card-stats">
                <div class="user-card-stat">
                    <span class="user-card-stat-val">${user.sessions.size}</span>
                    <span class="user-card-stat-lbl">Sessions</span>
                </div>
                <div class="user-card-stat">
                    <span class="user-card-stat-val">${user.events.length}</span>
                    <span class="user-card-stat-lbl">Events</span>
                </div>
                <div class="user-card-stat">
                    <span class="user-card-stat-val ${user.alerts > 0 ? 'red' : ''}">${user.alerts}</span>
                    <span class="user-card-stat-lbl">Alerts</span>
                </div>
                <div class="user-card-stat">
                    <span class="user-card-stat-val">${lastSeenStr}</span>
                    <span class="user-card-stat-lbl">Last Seen</span>
                </div>
            </div>
        `;
        grid.appendChild(card);
    });
}

function openUserDetail(ip) {
    selectedUserIp = ip;
    renderUsersView();
}

function closeUserDetail() {
    selectedUserIp = null;
    renderUsersView();
}

function renderUserDetail(user) {
    document.getElementById('user-detail-ip').textContent = user.ip;
    document.getElementById('user-detail-sessions').textContent = `${user.sessions.size} session${user.sessions.size !== 1 ? 's' : ''}`;
    document.getElementById('user-detail-events').textContent = `${user.events.length} events`;
    document.getElementById('user-detail-first-seen').textContent = `First seen: ${user.firstSeen ? new Date(user.firstSeen).toLocaleTimeString() : '--'}`;

    const badge = document.getElementById('user-detail-risk-badge');
    const level = user.maxSeverity === 'high' ? 'HIGH' : user.maxSeverity === 'medium' ? 'MEDIUM' : 'LOW';
    badge.textContent = level;
    badge.className = `badge ${level === 'HIGH' ? 'badge-high' : level === 'MEDIUM' ? 'badge-medium' : 'badge-low'}`;

    const tbody = document.getElementById('user-detail-body');
    tbody.innerHTML = '';

    const events = user.events.slice().sort((a, b) => {
        const ta = new Date(a.timestamp || 0).getTime();
        const tb = new Date(b.timestamp || 0).getTime();
        return tb - ta;
    });

    events.forEach(p => {
        const tr = document.createElement('tr');
        if (p.type === 'SECURITY_ALERT') tr.classList.add('alert-row');
        const time = p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : '--';
        const sev = severityFor(p);
        const sevClass = sev === 'high' ? 'badge-high' : sev === 'medium' ? 'badge-medium' : 'badge-low';
        const typeName = String(p.type || 'unknown').replace(/_/g, ' ');

        tr.innerHTML = `
            <td class="mono">${time}</td>
            <td><span class="badge badge-info">${escapeHtml(typeName)}</span></td>
            <td class="mono clickable trace-link" onclick="enterTraceMode('${escapeHtml(p.sessionId || '')}'); event.stopPropagation();">${escapeHtml(p.sessionId || '--')}</td>
            <td><span class="badge ${sevClass}">${sev}</span></td>
            <td style="font-size:0.8rem">${escapeHtml(summaryFor(p))}</td>
        `;
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
    summaryBody.innerHTML = `<div class="ai-loading"><div class="ai-loading-dots"><span></span><span></span><span></span></div><span>Analyzing ${body.ip ? body.ip : 'session'}...</span></div>`;
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
            throw new Error(err.error || `Request failed (${res.status})`);
        }

        const data = await res.json();
        summaryBody.innerHTML = renderAiMarkdown(data.summary, data.eventCount);
    } catch (error) {
        summaryBody.innerHTML = `<div class="ai-error">⚠ ${escapeHtml(error.message)}</div>`;
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a4 4 0 014 4v1a3 3 0 013 3v1a2 2 0 012 2v4a6 6 0 01-6 6h-6a6 6 0 01-6-6v-4a2 2 0 012-2v-1a3 3 0 013-3V6a4 4 0 014-4z"/><circle cx="9" cy="14" r="1"/><circle cx="15" cy="14" r="1"/></svg> ${mode === 'session' ? 'AI' : 'AI Summary'}`;
        }
    }
}

function renderAiMarkdown(text, eventCount) {
    if (!text) return '<div class="ai-error">No analysis generated.</div>';

    // Simple markdown → HTML
    let html = escapeHtml(text)
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>')
        .replace(/^- (.+)$/gm, '<li>$1</li>')
        .replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>')
        .replace(/\n{2,}/g, '</p><p>')
        .replace(/\n/g, '<br>');

    html = `<p>${html}</p>`;
    
    // Highlight verdict keywords
    html = html.replace(/(CLEAN|No Action Needed)/g, '<span class="ai-verdict ai-verdict-clean">$1</span>');
    html = html.replace(/(SUSPICIOUS|Challenge|Monitor)/g, '<span class="ai-verdict ai-verdict-suspicious">$1</span>');
    html = html.replace(/(MALICIOUS|BOT|Block|Escalate)/g, '<span class="ai-verdict ai-verdict-danger">$1</span>');

    return `<div class="ai-content">${html}</div><div class="ai-footer">${eventCount} events analyzed</div>`;
}

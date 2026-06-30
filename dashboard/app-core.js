// ===== STATE =====
let currentUser, userApiKey, userDomains = [];
let allEvents = [], currentFilter = 'all', alertCount = 0;
const uniqueSessions = new Set(), siteSessionMap = {}, siteAlertMap = {}, knownSites = new Map();
let authMode = 'login';
let evtSource;
let currentView = 'dashboard'; // dashboard | trace | summary | users | notes | history
let traceSessionId = null;
let selectedFlag = null;
let investigationAlert = null;

// ===== API =====
async function apiFetch(url, options = {}) {
    const headers = { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) };
    const response = await fetch(url, { ...options, headers, credentials: 'same-origin' });
    const text = await response.text();
    let data = {};
    try { 
        data = text ? JSON.parse(text) : {}; 
    } catch { 
        data = { error: text.trim().startsWith('<') ? `Request failed with status ${response.status}` : (text || `Request failed with status ${response.status}`) }; 
    }
    if (!response.ok) throw new Error(data.error || data.message || `Request failed with status ${response.status}`);
    return data;
}

function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

// ===== AUTH =====
async function initApp() {
    try {
        const data = await apiFetch('/api/auth/me');
        currentUser = data.user;
        await registerUser();
    } catch (error) {
        showView('login');
    }
}

function setAuthMode(mode) {
    if (authMode === mode) return;
    authMode = mode;
    document.getElementById('auth-error').style.display = 'none';
    document.getElementById('auth-success').style.display = 'none';
    document.getElementById('auth-email').value = '';
    document.getElementById('auth-password').value = '';
    document.getElementById('auth-password-confirm').value = '';
    document.getElementById('mode-login-btn').classList.toggle('active', mode === 'login');
    document.getElementById('mode-signup-btn').classList.toggle('active', mode === 'signup');
    if (mode === 'signup') {
        document.getElementById('auth-password-confirm').classList.remove('hidden');
        document.getElementById('auth-submit-btn').textContent = 'Create Account';
        document.getElementById('auth-title').textContent = 'Create an account to start monitoring';
    } else {
        document.getElementById('auth-password-confirm').classList.add('hidden');
        document.getElementById('auth-submit-btn').textContent = 'Sign In';
        document.getElementById('auth-title').textContent = 'Sign in to access your Security Command Center';
    }
}

async function submitAuth() { authMode === 'login' ? await handleLogin() : await handleSignup(); }
function loginWithGoogle() { window.location.href = '/api/auth/google?t=' + Date.now(); }

async function handleLogin() {
    const email = document.getElementById('auth-email').value.trim();
    const password = document.getElementById('auth-password').value;
    if (!email || !password) return showAuthError('Please enter email and password');
    setAuthBusy(true);
    try { const data = await apiFetch('/api/auth/login', { method:'POST', body:JSON.stringify({email,password}) }); currentUser = data.user; await registerUser(); }
    catch (error) { showAuthError(error.message); } finally { setAuthBusy(false); }
}

async function handleSignup() {
    const email = document.getElementById('auth-email').value.trim();
    const password = document.getElementById('auth-password').value;
    const confirm = document.getElementById('auth-password-confirm').value;
    if (!email || !password) return showAuthError('Please enter email and password');
    if (password !== confirm) return showAuthError('Passwords do not match');
    if (password.length < 6) return showAuthError('Password must be at least 6 characters');
    setAuthBusy(true);
    try {
        const data = await apiFetch('/api/auth/signup', { method:'POST', body:JSON.stringify({email,password}) });
        if (!data.hasSession) { setAuthMode('login'); showAuthSuccess(data.message || 'Account created! Check email then sign in.'); return; }
        currentUser = data.user; await registerUser();
    } catch (error) { showAuthError(error.message); } finally { setAuthBusy(false); }
}

function showAuthError(msg) { const el=document.getElementById('auth-error'); el.textContent=msg; el.style.display='block'; document.getElementById('auth-success').style.display='none'; }
function showAuthSuccess(msg) { const el=document.getElementById('auth-success'); el.textContent=msg; el.style.display='block'; document.getElementById('auth-error').style.display='none'; }

function setAuthBusy(isBusy) {
    const btn=document.getElementById('auth-submit-btn'), l=document.getElementById('mode-login-btn'), s=document.getElementById('mode-signup-btn');
    if(btn)btn.disabled=isBusy; if(l)l.disabled=isBusy; if(s)s.disabled=isBusy;
    if(btn){ if(isBusy){btn.dataset.originalText=btn.textContent;btn.textContent='Please wait...';}else{btn.textContent=btn.dataset.originalText||(authMode==='login'?'Sign In':'Create Account');}}
}

async function logout() {
    try { await apiFetch('/api/auth/logout',{method:'POST'}); } catch {}
    currentUser=null; userApiKey=null; userDomains=[]; resetRealtimeState(); showView('login');
}

async function registerUser() {
    const data = await apiFetch('/api/auth/register',{method:'POST'});
    userApiKey = data.apiKey; userDomains = data.allowedDomains || [];
    userDomains.length === 0 ? showOnboarding() : goToDashboard();
}

// ===== VIEWS =====
function showView(name) {
    document.getElementById('view-login').classList.toggle('hidden', name !== 'login');
    document.getElementById('view-onboard').classList.toggle('hidden', name !== 'onboard');
    document.getElementById('view-dashboard').classList.toggle('hidden', name !== 'dashboard');
}

function showOnboarding() {
    showView('onboard');
    document.getElementById('onboard-apikey').textContent = userApiKey;
    document.getElementById('onboard-snippet').textContent = buildSnippet();
    renderDomainList();
}

function buildSnippet() {
    const baseUrl = window.location.origin;
    return `<script type="module" src="${baseUrl}/sdk/index.js"><\/script>\n<script type="module">\n    import { MayaSec } from '${baseUrl}/sdk/index.js';\n    MayaSec.init({ apiKey: '${userApiKey}' });\n    MayaSec.start();\n<\/script>`;
}

function copyApiKey(trigger) {
    navigator.clipboard.writeText(userApiKey);
    const btn = trigger || document.querySelector('.copy-btn');
    if(!btn) return;
    const prev = btn.textContent; btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = prev, 1500);
}

function copySnippet(btn) {
    const wrapper = btn.closest('.snippet-wrapper');
    const snippetEl = wrapper ? wrapper.querySelector('.snippet-box') : null;
    if (!snippetEl) return;
    navigator.clipboard.writeText(snippetEl.textContent).then(() => {
        const prev = btn.textContent;
        btn.textContent = '✓ COPIED';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = prev; btn.classList.remove('copied'); }, 2000);
    });
}

// ===== DOMAINS =====
async function addDomain() {
    const input = document.getElementById('domain-input'), domain = input.value.trim();
    if(!domain) return;
    try { const data = await apiFetch('/api/auth/domains',{method:'POST',body:JSON.stringify({domain})}); userDomains=data.allowedDomains||[]; input.value=''; renderDomainList(); }
    catch(e){ showAuthError(e.message); }
}
async function removeDomain(domain) {
    try { const data = await apiFetch('/api/auth/domains',{method:'DELETE',body:JSON.stringify({domain})}); userDomains=data.allowedDomains||[]; renderDomainList(); }
    catch(e){ showAuthError(e.message); }
}
function renderDomainList() { renderDomainListInto(document.getElementById('domain-list')); renderDomainListInto(document.getElementById('settings-domain-list')); }
function renderDomainListInto(container) {
    if(!container) return; container.innerHTML='';
    userDomains.forEach(domain => { const chip=document.createElement('span'); chip.className='domain-chip'; chip.textContent=domain+' ';
        const rm=document.createElement('span'); rm.className='remove'; rm.textContent='×'; rm.onclick=()=>removeDomain(domain); chip.appendChild(rm); container.appendChild(chip); });
}
function openSettings() {
    document.getElementById('settings-apikey').textContent=userApiKey||'-';
    document.getElementById('settings-snippet').textContent=buildSnippet();
    document.getElementById('settings-domain-input').value=''; renderDomainList();
    document.getElementById('settings-modal').classList.remove('hidden');
}
function closeSettings() { document.getElementById('settings-modal').classList.add('hidden'); }
async function addDomainFromSettings() {
    const input=document.getElementById('settings-domain-input'), domain=input.value.trim();
    if(!domain) return;
    try { const data = await apiFetch('/api/auth/domains',{method:'POST',body:JSON.stringify({domain})}); userDomains=data.allowedDomains||[]; input.value=''; renderDomainList(); }
    catch(e){ showAuthError(e.message); closeSettings(); }
}

document.addEventListener('keydown', e => {
    if(e.key==='Escape') closeSettings();
    if(e.key==='Enter' && document.activeElement?.id==='settings-domain-input') addDomainFromSettings();
});

// ===== SSE + DASHBOARD =====
function goToDashboard() {
    showView('dashboard'); resetRealtimeState();
    const name = currentUser.user_metadata?.full_name || currentUser.email?.split('@')[0] || 'User';
    document.getElementById('user-name').textContent = name;
    document.getElementById('user-avatar').src = currentUser.user_metadata?.avatar_url || `https://ui-avatars.com/api/?name=${encodeURIComponent(currentUser.email)}&background=3b82f6&color=fff&size=64`;
    document.getElementById('settings-apikey').textContent = userApiKey||'-';
    document.getElementById('settings-snippet').textContent = buildSnippet();
    updateSiteDropdown();
    connectSSE();
}

function resetRealtimeState() {
    allEvents=[]; currentFilter='all'; alertCount=0;
    uniqueSessions.clear(); knownSites.clear();
    Object.keys(siteSessionMap).forEach(k=>delete siteSessionMap[k]);
    Object.keys(siteAlertMap).forEach(k=>delete siteAlertMap[k]);
    document.getElementById('events-body').innerHTML='';
    updateKPIs();
}

function connectSSE() {
    if(evtSource) evtSource.close();
    evtSource = new EventSource(`/api/events/stream?apiKey=${userApiKey}`);
    evtSource.onmessage = function(event) {
        const msg = JSON.parse(event.data);
        if(msg.type==='history'){ msg.data.reverse().forEach(p=>addEvent(p,false)); renderTable(); }
        else if(msg.type==='new_event'){ addEvent(msg.data,true); }
        else if(msg.type==='sites_update'){ updateSiteList(msg.data); }
    };
    evtSource.onerror = () => console.log('SSE Disconnected');
    evtSource.onopen = () => console.log('SSE System Online');
}

function selectSite(name) { currentFilter=name; updateSiteDropdown(); renderTable(); updateKPIs(); }
function selectSiteFromDropdown(val) { selectSite(val); }

function updateSiteDropdown() {
    const sel = document.getElementById('site-select');
    sel.innerHTML = '';
    
    const allSites = new Set(userDomains || []);
    knownSites.forEach((site, name) => allSites.add(name));
    
    // Always add an "All Sites" option first
    const allOpt = document.createElement('option');
    allOpt.value = 'all'; allOpt.textContent = 'All Sites';
    sel.appendChild(allOpt);

    allSites.forEach((name) => {
        const opt = document.createElement('option');
        opt.value = name; opt.textContent = name;
        sel.appendChild(opt);
    });
    
    if (currentFilter !== 'all' && !allSites.has(currentFilter)) {
        currentFilter = 'all';
        if (typeof renderTable === 'function') renderTable();
    }
    
    sel.value = currentFilter;
}



initApp();

// Virtual FIDO2 Token — Material Design 3 Client Application

let currentTab = 'dashboard';
let identities = [];
let pendingApproval = null;
let selectedAccountIndex = 0;
let logFilter = 'all';
let deleteTargetId = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  setupTabs();
  connectSSE();
  fetchStatus();
  loadIdentities();
  checkInstallerStatus();
  loadPINStatus();
});

// Sound notification using Web Audio API (Zero external assets)
function playNotificationChime() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(587.33, ctx.currentTime); // D5
    osc.frequency.setValueAtTime(880.00, ctx.currentTime + 0.1); // A5
    gain.gain.setValueAtTime(0.15, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.4);
  } catch (e) {
    // Audio context not allowed without interaction
  }
}

// Tab Switching
function switchTab(tabId) {
  currentTab = tabId;
  document.querySelectorAll('.m3-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

  const activeBtn = Array.from(document.querySelectorAll('.m3-tab')).find(b => b.textContent.toLowerCase().includes(tabId.slice(0, 4)));
  if (activeBtn) activeBtn.classList.add('active');

  const pane = document.getElementById(`pane-${tabId}`);
  if (pane) pane.classList.add('active');

  if (tabId === 'passkeys') loadIdentities();
  if (tabId === 'installer') checkInstallerStatus();
}

function setupTabs() {
  // handled by switchTab
}

// Server-Sent Events (SSE) for Real-Time Approval & Log Streaming
function connectSSE() {
  const evtSource = new EventSource('/api/events');

  evtSource.addEventListener('status', (e) => {
    try {
      const data = JSON.parse(e.data);
      updateStatusUI(data);
    } catch (err) {
      console.error('SSE status parse err', err);
    }
  });

  evtSource.addEventListener('approval_request', (e) => {
    try {
      const req = JSON.parse(e.data);
      handleApprovalRequest(req);
    } catch (err) {
      console.error('SSE approval parse err', err);
    }
  });

  evtSource.addEventListener('log', (e) => {
    try {
      const log = JSON.parse(e.data);
      appendLog(log);
    } catch (err) {
      console.error('SSE log parse err', err);
    }
  });

  evtSource.onerror = () => {
    // reconnects automatically
  };
}

// Daemon & USB Status
async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    if (res.ok) {
      const data = await res.json();
      updateStatusUI(data);
    }
  } catch (e) {
    console.warn('Status poll error', e);
  }
}

function updateStatusUI(data) {
  const statusChip = document.getElementById('status-chip');
  const statusDot = document.getElementById('status-dot');
  const statusText = document.getElementById('status-text');
  const usbChipText = document.getElementById('usb-port-text');
  const daemonBtn = document.getElementById('toggle-daemon-btn');
  const daemonBtnLabel = document.getElementById('daemon-btn-label');
  const profileStatus = document.getElementById('profile-status-badge');
  const statUsbPort = document.getElementById('stat-usb-port');
  const vaultPath = document.getElementById('vault-path-text');

  if (data.vault) {
    vaultPath.textContent = `${data.vault} (Encrypted)`;
  }

  if (data.running) {
    statusChip.className = 'm3-chip active';
    statusDot.className = 'pulse-dot';
    statusText.textContent = 'DAEMON ACTIVE';
    daemonBtnLabel.textContent = 'Stop Token';
    profileStatus.textContent = 'Active';
    profileStatus.className = 'm3-chip active';
  } else {
    statusChip.className = 'm3-chip stopped';
    statusDot.className = 'pulse-dot grey';
    statusText.textContent = 'DAEMON STOPPED';
    daemonBtnLabel.textContent = 'Start Token';
    profileStatus.textContent = 'Standby';
    profileStatus.className = 'm3-chip stopped';
  }

  if (data.attached) {
    usbChipText.textContent = data.port ? `Attached (${data.port})` : 'USB Attached';
    statUsbPort.textContent = data.port ? `${data.port} (Attached)` : 'Attached';
    statUsbPort.style.color = 'var(--md-sys-color-success)';
  } else {
    usbChipText.textContent = 'USB Detached';
    statUsbPort.textContent = 'Detached';
    statUsbPort.style.color = 'var(--md-sys-color-on-surface-variant)';
  }
}

async function toggleDaemon() {
  const btn = document.getElementById('toggle-daemon-btn');
  btn.disabled = true;
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    const endpoint = data.running ? '/api/stop' : '/api/start';
    const postRes = await fetch(endpoint, { method: 'POST' });
    const result = await postRes.json();
    if (result.error) {
      showToast(`Error: ${result.error}`);
    } else {
      showToast(data.running ? 'Token daemon stopped' : 'Token daemon active & attached');
    }
    fetchStatus();
  } catch (e) {
    showToast('Failed to toggle daemon');
  } finally {
    btn.disabled = false;
  }
}

async function attachUSB() {
  try {
    const res = await fetch('/api/start', { method: 'POST' });
    const data = await res.json();
    if (data.error) showToast(`Attach error: ${data.error}`);
    else showToast('Virtual USB device attached');
    fetchStatus();
  } catch (e) {
    showToast('Failed to attach USB');
  }
}

async function detachUSB() {
  try {
    const res = await fetch('/api/stop', { method: 'POST' });
    const data = await res.json();
    if (data.error) showToast(`Detach error: ${data.error}`);
    else showToast('Virtual USB device detached');
    fetchStatus();
  } catch (e) {
    showToast('Failed to detach USB');
  }
}

// Passkeys Vault Management
async function loadIdentities() {
  try {
    const res = await fetch('/api/identities');
    if (res.ok) {
      identities = await res.json();
      renderIdentities(identities);
      document.getElementById('stat-passkeys-count').textContent = identities.length;
      document.getElementById('vault-count-badge').textContent = `${identities.length} Passkey${identities.length === 1 ? '' : 's'}`;
    }
  } catch (e) {
    console.error('Failed to load identities', e);
  }
}

function renderIdentities(list) {
  const container = document.getElementById('passkey-list');
  if (!list || list.length === 0) {
    container.innerHTML = `
      <div class="empty-state" style="grid-column: 1 / -1;">
        <div class="empty-state-icon">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="currentColor">
            <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
          </svg>
        </div>
        <h3>No Passkeys Found</h3>
        <p style="font-size: 13px; margin-top: 6px;">Register on Telegram Desktop, GitHub, or any WebAuthn service to store passkeys in this vault.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = list.map(item => {
    const initial = (item.rpName || item.rpId || 'K')[0].toUpperCase();
    const hexPrefix = item.id.slice(0, 8);
    const displayName = item.userDisplayName || item.userName || 'Unknown User';
    const userName = item.userName || '';

    return `
      <div class="passkey-card">
        <div class="passkey-header">
          <div class="passkey-entity">
            <div class="passkey-avatar">${initial}</div>
            <div>
              <div class="passkey-rp-title">${escapeHtml(item.rpName || item.rpId)}</div>
              <div class="passkey-rp-domain">${escapeHtml(item.rpId)}</div>
            </div>
          </div>
          <button class="m3-icon-btn delete" title="Delete passkey" onclick="openDeleteModal('${item.id}', '${escapeHtml(item.rpName || item.rpId)}', '${escapeHtml(displayName)}')">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
              <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/>
            </svg>
          </button>
        </div>

        <div class="passkey-user-box">
          <div class="passkey-display-name">${escapeHtml(displayName)}</div>
          <div class="passkey-username">${escapeHtml(userName)}</div>
        </div>

        <div class="passkey-footer">
          <span class="id-badge" title="Click to copy Credential ID" onclick="copyToClipboard('${item.id}')">
            ID: ${hexPrefix}..
          </span>
          <span style="font-size: 11px; color: var(--md-sys-color-on-surface-variant);">
            Used: <b style="color: var(--md-sys-color-primary);">${item.signCount || 0}</b> times
          </span>
          <span class="m3-chip" style="padding: 3px 8px; font-size: 10px;">ES256</span>
        </div>
      </div>
    `;
  }).join('');
}

function filterPasskeys() {
  const query = document.getElementById('passkey-search-input').value.toLowerCase().trim();
  if (!query) {
    renderIdentities(identities);
    return;
  }
  const filtered = identities.filter(i => 
    (i.rpName && i.rpName.toLowerCase().includes(query)) ||
    (i.rpId && i.rpId.toLowerCase().includes(query)) ||
    (i.userName && i.userName.toLowerCase().includes(query)) ||
    (i.userDisplayName && i.userDisplayName.toLowerCase().includes(query)) ||
    (i.id && i.id.toLowerCase().includes(query))
  );
  renderIdentities(filtered);
}

function openDeleteModal(id, rp, user) {
  deleteTargetId = id;
  document.getElementById('delete-rp-name').textContent = rp;
  document.getElementById('delete-user-name').textContent = user;
  const modal = document.getElementById('delete-modal');
  modal.showModal();
}

function closeDeleteModal() {
  const modal = document.getElementById('delete-modal');
  modal.close();
  deleteTargetId = null;
}

async function confirmDeletePasskey() {
  if (!deleteTargetId) return;
  try {
    const res = await fetch(`/api/identities?id=${encodeURIComponent(deleteTargetId)}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.success) {
      showToast('Passkey deleted from vault');
      loadIdentities();
    } else {
      showToast(`Delete failed: ${data.error || 'Unknown error'}`);
    }
  } catch (e) {
    showToast('Failed to delete passkey');
  } finally {
    closeDeleteModal();
  }
}

// Live WebAuthn Approval Modal
function handleApprovalRequest(req) {
  pendingApproval = req;
  playNotificationChime();

  const modal = document.getElementById('approval-modal');
  const headline = document.getElementById('modal-headline');
  const supporting = document.getElementById('modal-supporting-text');
  const rpName = document.getElementById('modal-rp-name');
  const userName = document.getElementById('modal-user-name');
  const userRow = document.getElementById('modal-user-row');
  const multiContainer = document.getElementById('modal-multi-accounts-container');
  const accountsList = document.getElementById('modal-accounts-list');
  const approveBtn = document.getElementById('modal-btn-approve');

  rpName.textContent = req.relyingParty || 'Unknown Relying Party';

  if (req.type === 'make_credential') {
    headline.textContent = 'Create New Passkey';
    supporting.textContent = `"${req.relyingParty}" wants to register a new security key passkey on this device.`;
    userRow.style.display = req.userName ? 'flex' : 'none';
    userName.textContent = req.userName || '';
    multiContainer.style.display = 'none';
    approveBtn.textContent = 'Approve Creation';
  } else if (req.type === 'select_account') {
    headline.textContent = 'Select Passkey Account';
    supporting.textContent = `Multiple accounts found for "${req.relyingParty}". Choose which identity to sign in with:`;
    userRow.style.display = 'none';
    multiContainer.style.display = 'block';
    selectedAccountIndex = 0;

    accountsList.innerHTML = (req.accounts || []).map((acc, idx) => `
      <label class="account-option ${idx === 0 ? 'selected' : ''}" onclick="selectAccountRadio(${idx})">
        <input type="radio" name="account_choice" value="${idx}" ${idx === 0 ? 'checked' : ''}>
        <div class="account-option-info">
          <span class="account-option-title">${escapeHtml(acc.displayName || acc.name)}</span>
          <span class="account-option-sub">${escapeHtml(acc.name)} • ID: ${escapeHtml(acc.id ? acc.id.slice(0, 8) : '')}</span>
        </div>
      </label>
    `).join('');
    approveBtn.textContent = 'Sign In';
  } else {
    headline.textContent = 'Passkey Sign-In';
    supporting.textContent = `"${req.relyingParty}" requests authentication using your stored passkey.`;
    userRow.style.display = 'flex';
    userName.textContent = req.userDisplayName || req.userName || 'Account Identity';
    multiContainer.style.display = 'none';
    approveBtn.textContent = 'Approve Sign-In';
  }

  modal.showModal();
}

function selectAccountRadio(index) {
  selectedAccountIndex = index;
  document.querySelectorAll('.account-option').forEach((el, idx) => {
    if (idx === index) {
      el.classList.add('selected');
      const radio = el.querySelector('input[type="radio"]');
      if (radio) radio.checked = true;
    } else {
      el.classList.remove('selected');
    }
  });
}

async function respondApproval(approved) {
  const modal = document.getElementById('approval-modal');
  modal.close();

  if (!pendingApproval) return;
  const reqId = pendingApproval.id;
  pendingApproval = null;

  try {
    await fetch('/api/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: reqId,
        approved: approved,
        selectedIndex: selectedAccountIndex
      })
    });
    showToast(approved ? 'Request approved' : 'Request denied');
  } catch (e) {
    console.error('Error sending approval response', e);
  }
}

// Installer & Setup Wizard
async function checkInstallerStatus() {
  appendTerminal('[SETUP] Checking Windows kernel driver and environment state...', 'cmd');
  try {
    const res = await fetch('/api/installer/status');
    if (!res.ok) throw new Error('Status API error');
    const data = await res.json();

    // Step 1: Testsigning
    const bTest = document.getElementById('badge-testsigning');
    const cTest = document.getElementById('step-card-testsigning');
    const btnTest = document.getElementById('btn-enable-testsigning');
    if (data.testsigning) {
      bTest.className = 'm3-chip active';
      bTest.innerHTML = '&#10003; Enabled';
      cTest.classList.add('completed');
      btnTest.style.display = 'none';
    } else {
      bTest.className = 'm3-chip';
      bTest.textContent = 'Disabled';
      cTest.classList.remove('completed');
      btnTest.style.display = 'inline-flex';
    }

    // Step 2: Cert
    const bCert = document.getElementById('badge-cert');
    const cCert = document.getElementById('step-card-cert');
    const btnCert = document.getElementById('btn-install-cert');
    if (data.certificate) {
      bCert.className = 'm3-chip active';
      bCert.innerHTML = '&#10003; Trusted';
      cCert.classList.add('completed');
      btnCert.style.display = 'none';
    } else {
      bCert.className = 'm3-chip';
      bCert.textContent = 'Not Installed';
      cCert.classList.remove('completed');
      btnCert.style.display = 'inline-flex';
    }

    // Step 3: Driver
    const bDrv = document.getElementById('badge-driver');
    const cDrv = document.getElementById('step-card-driver');
    const btnDrv = document.getElementById('btn-install-driver');
    if (data.driver) {
      bDrv.className = 'm3-chip active';
      bDrv.innerHTML = '&#10003; Operational';
      cDrv.classList.add('completed');
      btnDrv.textContent = 'Reinstall Driver';
    } else {
      bDrv.className = 'm3-chip';
      bDrv.textContent = 'Not Installed';
      cDrv.classList.remove('completed');
      btnDrv.textContent = 'Install Driver';
    }

    // Step 4: Loopback / Port
    const bPort = document.getElementById('badge-port');
    const cPort = document.getElementById('step-card-port');
    if (data.portsOk) {
      bPort.className = 'm3-chip active';
      bPort.innerHTML = `&#10003; ${data.portDetails || 'Verified'}`;
      cPort.classList.add('completed');
    } else {
      bPort.className = 'm3-chip';
      bPort.textContent = 'Idle (No devices)';
      cPort.classList.remove('completed');
    }

    // Overall banner
    const overallChip = document.getElementById('wizard-overall-chip');
    const overallText = document.getElementById('wizard-overall-text');
    if (data.testsigning && data.certificate && data.driver) {
      overallChip.className = 'm3-chip active';
      overallText.textContent = 'SYSTEM READY';
      appendTerminal('[SUCCESS] All kernel prerequisites and USB/IP drivers are operational.', 'success');
    } else {
      overallChip.className = 'm3-chip stopped';
      overallText.textContent = 'ACTION REQUIRED';
      appendTerminal('[WARN] Some prerequisites are missing. Follow the steps above to configure.', 'err');
    }
  } catch (e) {
    appendTerminal(`[ERROR] Could not check status: ${e.message}`, 'err');
  }
}

async function enableTestsigning() {
  appendTerminal('[ACTION] Running: bcdedit.exe /set testsigning on...', 'cmd');
  try {
    const res = await fetch('/api/installer/testsigning', { method: 'POST' });
    const data = await res.json();
    appendTerminal(data.output || 'Testsigning setting updated.', data.success ? 'success' : 'err');
    if (data.success) {
      showToast('Testsigning enabled. PC restart may be required if first time.');
    } else {
      showToast('Error enabling testsigning (Run as Administrator)');
    }
    checkInstallerStatus();
  } catch (e) {
    appendTerminal(`[ERROR] ${e.message}`, 'err');
  }
}

async function installCert() {
  appendTerminal('[ACTION] Running: certutil -addstore -f "Root" usbip_test.pfx...', 'cmd');
  try {
    const res = await fetch('/api/installer/cert', { method: 'POST' });
    const data = await res.json();
    appendTerminal(data.output || 'Certificate added to Root store.', data.success ? 'success' : 'err');
    showToast(data.success ? 'USB/IP Root Certificate Installed!' : 'Certificate installation failed');
    checkInstallerStatus();
  } catch (e) {
    appendTerminal(`[ERROR] ${e.message}`, 'err');
  }
}

async function installDriver() {
  appendTerminal('[ACTION] Running: usbip.exe install -u (Installing VHCI UDE driver)...', 'cmd');
  try {
    const res = await fetch('/api/installer/driver', { method: 'POST' });
    const data = await res.json();
    appendTerminal(data.output || 'Driver installation completed.', data.success ? 'success' : 'err');
    showToast(data.success ? 'VHCI Driver Installed Successfully!' : 'Driver installation returned errors');
    checkInstallerStatus();
    fetchStatus();
  } catch (e) {
    appendTerminal(`[ERROR] ${e.message}`, 'err');
  }
}

async function uninstallDriver() {
  if (!confirm('Are you sure you want to uninstall the USB/IP VHCI driver?')) return;
  appendTerminal('[ACTION] Running: usbip.exe uninstall -u...', 'cmd');
  try {
    const res = await fetch('/api/installer/uninstall', { method: 'POST' });
    const data = await res.json();
    appendTerminal(data.output || 'Driver uninstalled.', 'out');
    showToast('Driver uninstalled');
    checkInstallerStatus();
    fetchStatus();
  } catch (e) {
    appendTerminal(`[ERROR] ${e.message}`, 'err');
  }
}

async function testLoopback() {
  appendTerminal('[ACTION] Querying USB/IP port status: usbip.exe port...', 'cmd');
  try {
    const res = await fetch('/api/installer/diagnose', { method: 'POST' });
    const data = await res.json();
    appendTerminal(data.output || 'Port check complete.', 'out');
    checkInstallerStatus();
  } catch (e) {
    appendTerminal(`[ERROR] ${e.message}`, 'err');
  }
}

function appendTerminal(msg, type = 'out') {
  const terminal = document.getElementById('installer-terminal');
  const line = document.createElement('div');
  line.className = `terminal-line ${type}`;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

function clearTerminal() {
  document.getElementById('installer-terminal').innerHTML = '';
}

// Event Logs Tab
function appendLog(log) {
  const container = document.getElementById('logs-container');
  const entry = document.createElement('div');
  entry.className = 'log-entry';

  let tagClass = '';
  if (log.tag.includes('CTAP')) tagClass = 'ctap';
  else if (log.tag.includes('USBIP')) tagClass = 'usbip';
  else if (log.tag.includes('ERR')) tagClass = 'err';

  entry.innerHTML = `
    <span class="log-time">${escapeHtml(log.time || new Date().toLocaleTimeString())}</span>
    <span class="log-tag ${tagClass}">[${escapeHtml(log.tag)}]</span>
    <span class="log-msg">${escapeHtml(log.message)}</span>
  `;

  // filter
  if (logFilter !== 'all' && !log.tag.includes(logFilter)) {
    entry.style.display = 'none';
  }

  container.appendChild(entry);
  if (document.getElementById('autoscroll-chk').checked) {
    container.scrollTop = container.scrollHeight;
  }
}

function setLogFilter(filter) {
  logFilter = filter;
  document.querySelectorAll('.logs-filters .m3-chip').forEach(c => c.classList.remove('active'));
  const btn = document.getElementById(`filter-${filter.toLowerCase()}`);
  if (btn) btn.classList.add('active');

  const entries = document.querySelectorAll('.log-entry');
  entries.forEach(e => {
    if (filter === 'all') {
      e.style.display = 'flex';
    } else {
      const tag = e.querySelector('.log-tag').textContent;
      e.style.display = tag.includes(filter) ? 'flex' : 'none';
    }
  });
}

function clearLogs() {
  document.getElementById('logs-container').innerHTML = '';
}

// PIN Settings
async function loadPINStatus() {
  try {
    const res = await fetch('/api/pin');
    if (res.ok) {
      const data = await res.json();
      document.getElementById('pin-toggle-chk').checked = !!data.enabled;
    }
  } catch (e) {
    console.warn('Failed to load PIN status', e);
  }
}

async function togglePINProtection() {
  const chk = document.getElementById('pin-toggle-chk');
  try {
    const res = await fetch('/api/pin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: chk.checked ? 'enable' : 'disable' })
    });
    const data = await res.json();
    showToast(chk.checked ? 'PIN Protection Enabled' : 'PIN Protection Disabled');
  } catch (e) {
    showToast('Failed to change PIN protection');
    chk.checked = !chk.checked;
  }
}

async function saveNewPIN() {
  const input = document.getElementById('new-pin-input');
  const val = input.value.trim();
  if (val.length < 4 || isNaN(val)) {
    showToast('PIN must be at least 4 digits');
    return;
  }
  try {
    const res = await fetch('/api/pin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'set', pin: val })
    });
    const data = await res.json();
    if (data.success) {
      showToast('New PIN configured successfully');
      input.value = '';
      document.getElementById('pin-toggle-chk').checked = true;
    } else {
      showToast(`Error: ${data.error || 'Failed to set PIN'}`);
    }
  } catch (e) {
    showToast('Failed to save PIN');
  }
}

// Utility: Toast
function showToast(msg, duration = 3000) {
  const toast = document.getElementById('toast');
  const text = document.getElementById('toast-text');
  text.textContent = msg;
  toast.style.display = 'flex';
  setTimeout(() => {
    toast.style.display = 'none';
  }, duration);
}

// Utility: Clipboard
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('Credential ID copied to clipboard');
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

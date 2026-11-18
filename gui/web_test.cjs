const { readFileSync } = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const elements = new Map();
const document = {
  addEventListener() {},
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, { style: {}, classList: { add() {}, remove() {} }, appendChild() {} });
    return elements.get(id);
  },
  createElement() { return {}; }
};
let response;
let calls = 0;
const context = vm.createContext({ document, console, setTimeout() {}, fetch: async () => { calls++; return { ok: true, json: async () => response }; } });
vm.runInContext(readFileSync(`${__dirname}/web/app.js`, 'utf8'), context);

(async () => {
  response = { signedInstalled: true, driver: true, portsOk: false };
  await context.checkInstallerStatus();
  assert.equal(document.getElementById('wizard-overall-text').textContent, 'SYSTEM READY');
  assert.equal(document.getElementById('btn-install-driver').textContent, 'Repair signed USBip');
  response.driver = false;
  response.signedInstalled = false;
  await context.checkInstallerStatus();
  assert.equal(document.getElementById('wizard-overall-text').textContent, 'ACTION REQUIRED');
  assert.equal(document.getElementById('btn-install-driver').textContent, 'Install signed USBip');
  response.installing = true;
  await context.checkInstallerStatus();
  assert.equal(document.getElementById('btn-install-driver').disabled, true);
  response = { enabled: true };
  await context.loadPINStatus();
  assert.equal(document.getElementById('pin-toggle-chk').checked, true);
  response = { success: false };
  await context.togglePINProtection();
  assert.equal(document.getElementById('pin-toggle-chk').checked, false);
  const before = calls;
  document.getElementById('new-pin-input').value = '1e10';
  await context.saveNewPIN();
  assert.equal(calls, before, 'invalid PIN was sent to the API');
  response = { success: true };
  document.getElementById('new-pin-input').value = '001234';
  await context.saveNewPIN();
  assert.equal(document.getElementById('pin-toggle-chk').checked, true);
  assert.equal(document.getElementById('new-pin-input').value, '');
  document.getElementById('approval-modal').close = () => {};
  let toast;
  context.showToast = message => { toast = message; };
  context.fetch = async () => ({ ok: false, text: async () => 'Request expired' });
  vm.runInContext('pendingApproval = { id: "expired" }', context);
  await context.respondApproval(true);
  assert.equal(toast, 'Request expired', 'expired approval was shown as success');
  context.fetch = async () => ({ ok: true, json: async () => ({ success: true }) });
  vm.runInContext('pendingApproval = { id: "pending" }', context);
  await context.respondApproval(true);
  assert.equal(toast, 'Approval sent; wait for the website to finish');
  console.log('PASS: signed setup and PIN UI flows (mock DOM/API)');
})().catch(err => { console.error(err); process.exitCode = 1; });

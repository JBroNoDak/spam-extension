/**
 * Gmail Phishing Guard - Popup Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const toggleScanning = document.getElementById('toggleScanning');
  const statusBadge = document.getElementById('statusBadge');
  const emailsScanned = document.getElementById('emailsScanned');
  const threatsBlocked = document.getElementById('threatsBlocked');
  const linksInspected = document.getElementById('linksInspected');
  const attachmentsFlagged = document.getElementById('attachmentsFlagged');
  const whitelistInput = document.getElementById('whitelistInput');
  const addWhitelistBtn = document.getElementById('addWhitelistBtn');
  const whitelistTags = document.getElementById('whitelistTags');

  let currentWhitelist = ['company.com', 'trusted-partner.org'];

  function updateUI(data) {
    if (data.enabled !== undefined) {
      toggleScanning.checked = data.enabled;
      if (data.enabled) {
        statusBadge.innerText = '● ACTIVE';
        statusBadge.className = 'status-badge';
      } else {
        statusBadge.innerText = '○ PAUSED';
        statusBadge.className = 'status-badge disabled';
      }
    }

    if (data.stats) {
      emailsScanned.innerText = data.stats.emailsScanned || 0;
      threatsBlocked.innerText = data.stats.threatsBlocked || 0;
      linksInspected.innerText = data.stats.linksInspected || 0;
      attachmentsFlagged.innerText = data.stats.attachmentsFlagged || 0;
    }

    if (data.whitelist) {
      currentWhitelist = data.whitelist;
      renderWhitelist();
    }
  }

  function renderWhitelist() {
    whitelistTags.innerHTML = '';
    currentWhitelist.forEach((domain) => {
      const tag = document.createElement('span');
      tag.style.cssText = 'background:#334155; padding: 2px 6px; border-radius: 4px; font-size: 10px; display: inline-flex; align-items: center; gap: 4px;';
      tag.innerHTML = `${domain} <span style="cursor:pointer; color:#94a3b8;" data-domain="${domain}">×</span>`;
      tag.querySelector('span').addEventListener('click', (e) => {
        const d = e.target.getAttribute('data-domain');
        currentWhitelist = currentWhitelist.filter(x => x !== d);
        saveSettings();
        renderWhitelist();
      });
      whitelistTags.appendChild(tag);
    });
  }

  function saveSettings() {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.sync) {
      chrome.storage.sync.set({
        enabled: toggleScanning.checked,
        whitelist: currentWhitelist,
      });
    }
  }

  toggleScanning.addEventListener('change', () => {
    saveSettings();
    updateUI({ enabled: toggleScanning.checked });
  });

  addWhitelistBtn.addEventListener('click', () => {
    const val = whitelistInput.value.trim().toLowerCase();
    if (val && !currentWhitelist.includes(val)) {
      currentWhitelist.push(val);
      whitelistInput.value = '';
      saveSettings();
      renderWhitelist();
    }
  });

  // Load initial settings if in chrome extension context
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.sync) {
    chrome.storage.sync.get(['enabled', 'stats', 'whitelist'], (items) => {
      updateUI(items);
    });
  } else {
    renderWhitelist();
  }
});

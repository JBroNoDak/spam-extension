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
  const rescanGmailBtn = document.getElementById('rescanGmailBtn');
  const rescanFeedback = document.getElementById('rescanFeedback');

  let currentWhitelist = ['company.com', 'trusted-partner.org'];

  function cleanDomain(input) {
    if (!input) return '';
    let str = String(input).trim().toLowerCase();
    str = str.replace(/^mailto:/, '');
    str = str.replace(/^https?:\/\//, '');
    if (str.includes('@')) {
      str = str.split('@').pop();
    }
    str = str.split('/')[0].split(':')[0].split('?')[0];
    str = str.replace(/^www\./, '').replace(/^@+/, '').replace(/^\.+/, '');
    return str;
  }

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

    if (data.whitelist && Array.isArray(data.whitelist)) {
      currentWhitelist = data.whitelist.map(cleanDomain).filter(Boolean);
      renderWhitelist();
    }
  }

  function renderWhitelist() {
    whitelistTags.innerHTML = '';
    if (currentWhitelist.length === 0) {
      whitelistTags.innerHTML = '<span style="color: #64748b; font-size: 10px;">No custom domains added yet.</span>';
      return;
    }

    currentWhitelist.forEach((domain) => {
      const tag = document.createElement('span');
      tag.style.cssText = 'background:#334155; padding: 3px 8px; border-radius: 4px; font-size: 11px; display: inline-flex; align-items: center; gap: 6px; font-weight: 500; border: 1px solid #475569;';
      tag.innerHTML = `<span>🏢 ${domain}</span> <span style="cursor:pointer; color:#94a3b8; font-weight: bold; font-size: 13px;" data-domain="${domain}" title="Remove domain">&times;</span>`;
      tag.querySelector('span[data-domain]').addEventListener('click', (e) => {
        const d = e.target.getAttribute('data-domain');
        currentWhitelist = currentWhitelist.filter(x => x !== d);
        saveSettings();
        renderWhitelist();
        notifyGmailTabs();
      });
      whitelistTags.appendChild(tag);
    });
  }

  function saveSettings(callback) {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.sync) {
      chrome.storage.sync.set({
        enabled: toggleScanning.checked,
        whitelist: currentWhitelist,
        internalDomains: currentWhitelist,
      }, () => {
        if (callback) callback();
      });
    } else {
      if (callback) callback();
    }
  }

  function notifyGmailTabs() {
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.query({ url: "*://mail.google.com/*" }, (tabs) => {
        if (tabs && tabs.length > 0) {
          tabs.forEach((tab) => {
            if (tab.id) {
              chrome.tabs.sendMessage(tab.id, {
                type: 'UPDATE_CONFIG',
                config: {
                  whitelist: currentWhitelist,
                  internalDomains: currentWhitelist,
                  enabled: toggleScanning.checked,
                }
              }, () => {
                // Ignore errors if content script not yet injected
                if (chrome.runtime.lastError) { /* silent */ }
              });
            }
          });
        }
      });
    }
  }

  toggleScanning.addEventListener('change', () => {
    saveSettings();
    updateUI({ enabled: toggleScanning.checked });
    notifyGmailTabs();
  });

  function addDomain() {
    const raw = whitelistInput.value;
    const domain = cleanDomain(raw);
    if (domain && !currentWhitelist.includes(domain)) {
      currentWhitelist.push(domain);
      whitelistInput.value = '';
      saveSettings(() => {
        renderWhitelist();
        notifyGmailTabs();
      });
    }
  }

  addWhitelistBtn.addEventListener('click', addDomain);
  whitelistInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addDomain();
    }
  });

  if (rescanGmailBtn) {
    rescanGmailBtn.addEventListener('click', () => {
      saveSettings(() => {
        notifyGmailTabs();
        if (rescanFeedback) {
          rescanFeedback.style.display = 'block';
          rescanFeedback.innerText = `✓ Saved ${currentWhitelist.length} domains! Rescanning active Gmail tabs...`;
          setTimeout(() => {
            rescanFeedback.style.display = 'none';
          }, 3500);
        }
      });
    });
  }

  // Load initial settings if in chrome extension context
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.sync) {
    chrome.storage.sync.get(['enabled', 'stats', 'whitelist', 'internalDomains'], (items) => {
      if (items) {
        if (items.internalDomains && !items.whitelist) {
          items.whitelist = items.internalDomains;
        }
        updateUI(items);
      }
    });
  } else {
    renderWhitelist();
  }
});

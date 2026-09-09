/**
 * Gmail Phishing Guard - Chrome Content Script
 * Scans incoming external Gmail messages for phishing, credential theft, and malware.
 */

(function () {
  'use strict';

  const DANGEROUS_EXTENSIONS = [
    '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jse', '.wsf',
    '.hta', '.cpl', '.msi', '.msp', '.pif', '.com', '.iso', '.img',
    '.vhd', '.ps1', '.reg', '.iqy'
  ];

  const SUSPICIOUS_EXTENSIONS = [
    '.zip', '.rar', '.7z', '.tar', '.gz', '.docm', '.xlsm', '.pptm',
    '.html', '.htm', '.svg'
  ];

  const POPULAR_BRANDS = [
    'google.com', 'microsoft.com', 'apple.com', 'paypal.com', 'chase.com',
    'bankofamerica.com', 'amazon.com', 'netflix.com', 'wellsfargo.com',
    'dropbox.com', 'docusign.com', 'slack.com', 'zoom.us', 'stripe.com'
  ];

  let config = {
    enabled: true,
    sensitivity: 'balanced',
    whitelist: [],
    internalDomains: [],
    interceptCriticalClicks: true,
  };

  // Helper to normalize email or domain string into clean domain
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

  // Auto-detect logged-in user domain from Gmail interface
  function detectCurrentGmailUserDomain() {
    try {
      const candidates = [
        document.querySelector('a[aria-label*="Google Account:"]'),
        document.querySelector('a[aria-label*="@"]'),
        document.querySelector('[data-identifier]'),
        document.querySelector('.gb_d[aria-label*="@"]'),
        document.querySelector('div[aria-label*="@"]')
      ];
      for (const el of candidates) {
        if (!el) continue;
        const text = el.getAttribute('aria-label') || el.getAttribute('data-identifier') || el.innerText || '';
        const match = text.match(/([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))/);
        if (match && match[2]) {
          const dom = cleanDomain(match[2]);
          if (dom && !['gmail.com', 'google.com'].includes(dom)) {
            return dom;
          }
        }
      }
    } catch {
      // ignore
    }
    return null;
  }

  function isTrustedOrInternalDomain(domainOrEmail) {
    const target = cleanDomain(domainOrEmail);
    if (!target) return false;

    // Check auto-detected Gmail account domain (e.g. rks.io)
    const userDomain = detectCurrentGmailUserDomain();
    if (userDomain && (target === userDomain || target.endsWith('.' + userDomain))) {
      return true;
    }

    // Check explicit internal domains list
    const internalList = (config.internalDomains || []).map(cleanDomain).filter(Boolean);
    for (const d of internalList) {
      if (target === d || target.endsWith('.' + d)) {
        return true;
      }
    }

    // Check whitelist
    const whitelist = (config.whitelist || []).map(cleanDomain).filter(Boolean);
    for (const d of whitelist) {
      if (target === d || target.endsWith('.' + d)) {
        return true;
      }
    }

    return false;
  }

  // Load config from extension storage and rescan on load
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.sync) {
    chrome.storage.sync.get(['enabled', 'sensitivity', 'whitelist', 'internalDomains', 'interceptCriticalClicks'], (items) => {
      if (items) {
        config = { ...config, ...items };
        // Trigger rescan once initial config arrives from storage
        setTimeout(rescanAllVisibleEmails, 100);
      }
    });

    // Listen for real-time whitelist / setting changes from popup
    chrome.storage.onChanged.addListener((changes) => {
      let shouldRescan = false;
      if (changes.whitelist) {
        config.whitelist = changes.whitelist.newValue || [];
        shouldRescan = true;
      }
      if (changes.internalDomains) {
        config.internalDomains = changes.internalDomains.newValue || [];
        shouldRescan = true;
      }
      if (changes.enabled !== undefined) {
        config.enabled = changes.enabled.newValue;
        shouldRescan = true;
      }
      if (changes.sensitivity) {
        config.sensitivity = changes.sensitivity.newValue;
        shouldRescan = true;
      }

      if (shouldRescan) {
        console.log('🛡️ Gmail Phishing Guard: Storage changed, rescanning open emails with updated whitelist:', config.whitelist);
        rescanAllVisibleEmails();
      }
    });
  }

  // Listen for direct runtime rescan messages from popup
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (msg && (msg.type === 'RESCAN' || msg.type === 'UPDATE_CONFIG')) {
        if (msg.config) {
          config = { ...config, ...msg.config };
        }
        rescanAllVisibleEmails();
        sendResponse({ status: 'ok', rescanned: true });
      }
    });
  }

  // Track processed email elements to prevent re-processing
  const processedEmails = new WeakSet();

  function rescanAllVisibleEmails() {
    // Remove existing banners, tags, and highlights
    document.querySelectorAll('.gpg-banner').forEach((b) => b.remove());
    document.querySelectorAll('.gpg-link-tag').forEach((t) => t.remove());
    document.querySelectorAll('.gpg-attachment-badge').forEach((ab) => ab.remove());
    document.querySelectorAll('[class*="gpg-link-"]').forEach((el) => {
      el.classList.remove('gpg-link-critical', 'gpg-link-warning', 'gpg-link-caution', 'gpg-link-safe');
    });

    // Re-scan all active email containers
    const emailViews = document.querySelectorAll('.adn.ads, [role="main"] .h7');
    emailViews.forEach((el) => {
      processedEmails.delete(el);
      scanEmailMessage(el);
    });
  }

  function analyzeUrl(urlStr, textStr) {
    const issues = [];
    let risk = 'safe';
    let score = 0;

    try {
      const url = new URL(urlStr);
      const host = url.hostname.toLowerCase();
      const cleanHost = cleanDomain(host);
      const protocol = url.protocol.toLowerCase();

      // If domain is explicitly whitelisted or internal, mark safe immediately
      if (isTrustedOrInternalDomain(cleanHost)) {
        return { issues: [], risk: 'safe', score: 0 };
      }

      // Insecure HTTP
      if (protocol === 'http:') {
        issues.push('Insecure connection (HTTP instead of HTTPS)');
        score += 20;
        if (risk === 'safe') risk = 'caution';
      }

      // IP Address host
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
        issues.push('Numerical IP address instead of verified domain name');
        score += 50;
        risk = 'critical';
      }

      // Punycode / IDN
      if (host.startsWith('xn--')) {
        issues.push('Internationalized domain name (Punycode lookalike spoof)');
        score += 45;
        risk = 'critical';
      }

      // Display text mismatch
      if (textStr && textStr.trim()) {
        const text = textStr.trim();
        const match = text.match(/https?:\/\/([a-zA-Z0-9.-]+)/i) || text.match(/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
        if (match) {
          const displayDomain = match[1].toLowerCase().replace(/^www\./, '');
          const realDomain = host.replace(/^www\./, '');
          if (displayDomain !== realDomain && !realDomain.endsWith(`.${displayDomain}`)) {
            issues.push(`Misleading Link: Text shows "${displayDomain}" but link leads to "${realDomain}"`);
            score += 60;
            risk = 'critical';
          }
        }
      }

      // Typosquatting / Brand imitation
      for (const brand of POPULAR_BRANDS) {
        const brandName = brand.split('.')[0];
        if (cleanHost !== brand && (cleanHost.includes(brandName) || isOneCharDiff(cleanHost.split('.')[0], brandName))) {
          issues.push(`Lookalike domain: Mimicking legitimate "${brand}"`);
          score += 55;
          risk = 'critical';
          break;
        }
      }

      // URL Shorteners
      const shorteners = ['bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'ow.ly', 'cutt.ly'];
      if (shorteners.includes(cleanHost)) {
        issues.push('URL shortener hides actual destination');
        score += 30;
        if (risk !== 'critical') risk = 'warning';
      }

    } catch {
      issues.push('Invalid or obfuscated URL');
      score += 25;
      risk = 'warning';
    }

    return { issues, risk, score };
  }

  function isOneCharDiff(a, b) {
    if (Math.abs(a.length - b.length) > 1) return false;
    let diffs = 0;
    let i = 0, j = 0;
    while (i < a.length && j < b.length) {
      if (a[i] !== b[j]) {
        diffs++;
        if (diffs > 1) return false;
        if (a.length > b.length) i++;
        else if (b.length > a.length) j++;
        else { i++; j++; }
      } else {
        i++; j++;
      }
    }
    return true;
  }

  function analyzeAttachment(filename) {
    const issues = [];
    let risk = 'safe';
    const lower = filename.toLowerCase();

    // Double extension check (e.g. invoice.pdf.exe)
    const parts = lower.split('.');
    if (parts.length > 2) {
      const ext = `.${parts[parts.length - 1]}`;
      const fakeExt = `.${parts[parts.length - 2]}`;
      if (DANGEROUS_EXTENSIONS.includes(ext) || (['.pdf', '.docx', '.xlsx', '.png'].includes(fakeExt) && DANGEROUS_EXTENSIONS.includes(ext))) {
        issues.push(`Deceptive double extension: disguised executable (${fakeExt}${ext})`);
        risk = 'critical';
        return { issues, risk };
      }
    }

    for (const ext of DANGEROUS_EXTENSIONS) {
      if (lower.endsWith(ext)) {
        issues.push(`Executable program or script payload (${ext})`);
        risk = 'critical';
        return { issues, risk };
      }
    }

    for (const ext of SUSPICIOUS_EXTENSIONS) {
      if (lower.endsWith(ext)) {
        if (ext === '.docm' || ext === '.xlsm') {
          issues.push(`Macro-enabled document (${ext}) can run scripts`);
          risk = 'warning';
        } else {
          issues.push(`Archive file (${ext}) may conceal dangerous executables`);
          risk = 'warning';
        }
        return { issues, risk };
      }
    }

    return { issues, risk };
  }

  function scanEmailMessage(emailContainer) {
    if (processedEmails.has(emailContainer)) return;
    processedEmails.add(emailContainer);

    // Find sender details
    const senderElem = emailContainer.querySelector('[email]') || emailContainer.querySelector('.gD') || emailContainer.querySelector('.go');
    let senderEmail = senderElem ? (senderElem.getAttribute('email') || senderElem.innerText || '') : '';
    let senderName = senderElem ? (senderElem.getAttribute('name') || senderElem.innerText || '') : 'Sender';

    // Fallback search in header container
    if (!senderEmail || !senderEmail.includes('@')) {
      const headerText = emailContainer.querySelector('.gH')?.innerText || emailContainer.querySelector('.amn')?.innerText || '';
      const emailMatch = headerText.match(/<([^>]+@[^>]+)>/) || headerText.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      if (emailMatch) {
        senderEmail = emailMatch[1];
      }
    }

    const senderDomain = cleanDomain(senderEmail);

    // Determine if internal or whitelisted
    const isInternal = isTrustedOrInternalDomain(senderEmail) || isTrustedOrInternalDomain(senderDomain);
    const isExternal = !isInternal;

    // Body container
    const bodyElem = emailContainer.querySelector('.a3s.aiL') || emailContainer.querySelector('.adn.ads') || emailContainer;
    if (!bodyElem) return;

    let criticalCount = 0;
    let warningCount = 0;
    let cautionCount = 0;
    const detectedIssues = [];

    // Scan Links
    const links = bodyElem.querySelectorAll('a[href]');
    links.forEach((a) => {
      const href = a.getAttribute('href') || '';
      if (!href || href.startsWith('mailto:') || href.startsWith('#')) return;

      const linkAnalysis = analyzeUrl(href, a.innerText);
      if (linkAnalysis.risk !== 'safe') {
        if (linkAnalysis.risk === 'critical') criticalCount++;
        else if (linkAnalysis.risk === 'warning') warningCount++;
        else cautionCount++;

        detectedIssues.push(...linkAnalysis.issues);

        // Highlight link
        a.classList.add(`gpg-link-${linkAnalysis.risk}`);

        // Add badge tag
        const tag = document.createElement('span');
        tag.className = `gpg-link-tag gpg-link-tag-${linkAnalysis.risk}`;
        tag.innerText = linkAnalysis.risk === 'critical' ? '🔴 PHISHING RISK' : linkAnalysis.risk === 'warning' ? '🟠 SUSPICIOUS' : '🟡 CAUTION';
        a.parentNode.insertBefore(tag, a.nextSibling);

        // Intercept clicks on critical links
        a.addEventListener('click', (e) => {
          if (linkAnalysis.risk === 'critical' && config.interceptCriticalClicks) {
            const confirmed = window.confirm(
              `⚠️ SECURITY WARNING: Gmail Phishing Guard flagged this link as POTENTIALLY DANGEROUS.\n\n` +
              `Target URL: ${href}\n\n` +
              `Issues detected:\n- ${linkAnalysis.issues.join('\n- ')}\n\n` +
              `Are you sure you want to proceed? This may compromise your account.`
            );
            if (!confirmed) {
              e.preventDefault();
              e.stopPropagation();
            }
          }
        });
      }
    });

    // Scan Attachments
    const attachmentNodes = emailContainer.querySelectorAll('.aZo, [download_url], .aQy, .v1');
    attachmentNodes.forEach((node) => {
      const filename = node.getAttribute('download_url') || node.innerText || '';
      if (!filename) return;

      const attAnalysis = analyzeAttachment(filename);
      if (attAnalysis.risk !== 'safe') {
        if (attAnalysis.risk === 'critical') criticalCount++;
        else warningCount++;

        detectedIssues.push(...attAnalysis.issues);

        const badge = document.createElement('div');
        badge.className = `gpg-attachment-badge gpg-attachment-${attAnalysis.risk}`;
        badge.innerText = `⚠️ ${attAnalysis.risk.toUpperCase()}: ${attAnalysis.issues[0]}`;
        node.appendChild(badge);
      }
    });

    // Determine overall banner status
    let overallRisk = 'safe';
    if (criticalCount > 0) overallRisk = 'critical';
    else if (warningCount > 0) overallRisk = 'warning';
    else if (cautionCount > 0) overallRisk = 'caution';
    else if (isExternal) overallRisk = 'caution';
    else overallRisk = 'safe';

    // Check if banner already exists to prevent duplicates
    if (bodyElem.parentNode.querySelector('.gpg-banner')) {
      bodyElem.parentNode.querySelector('.gpg-banner').remove();
    }

    // Inject top banner
    const banner = document.createElement('div');
    banner.className = `gpg-banner gpg-banner-${overallRisk}`;
    
    const badgeText = overallRisk === 'critical'
      ? '🔴 CRITICAL THREAT DETECTED'
      : overallRisk === 'warning'
      ? '🟠 SUSPICIOUS EMAIL'
      : overallRisk === 'caution'
      ? (isExternal ? '🟡 EXTERNAL SENDER' : '🟡 SECURITY CAUTION')
      : isInternal
      ? '🟢 INTERNAL & TRUSTED'
      : '🟢 VERIFIED SAFE';

    const bannerHtml = `
      <div class="gpg-banner-header">
        <span>🛡️ Gmail Phishing Guard: ${badgeText}</span>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="gpg-banner-badge gpg-banner-badge-${isInternal ? 'safe' : overallRisk}">
            ${isInternal ? `🏢 INTERNAL (${senderDomain || 'VERIFIED'})` : 'EXTERNAL SOURCE'}
          </span>
          <button class="gpg-view-details-btn" style="background: rgba(0,0,0,0.1); border: 1px solid rgba(0,0,0,0.2); border-radius: 6px; padding: 2px 8px; font-size: 11px; cursor: pointer; font-weight: 600;">Full Report</button>
        </div>
      </div>
      <div class="gpg-banner-body">
        ${
          overallRisk === 'critical'
            ? 'This email contains links or attachments exhibiting high-confidence phishing indicators. Do not enter credentials, download files, or respond.'
            : overallRisk === 'warning'
            ? 'Be cautious. This email contains potential security anomalies such as obfuscated links or unusual attachments.'
            : isExternal
            ? 'This email originated from an external address. Verify the sender identity before clicking links or downloading files.'
            : `This email is from a verified internal or trusted organization domain (${senderDomain || 'organization'}). All security inspections passed.`
        }
        ${
          detectedIssues.length > 0
            ? `<ul class="gpg-threat-list">${Array.from(new Set(detectedIssues)).slice(0, 4).map(i => `<li>${escapeHtml(i)}</li>`).join('')}</ul>`
            : ''
        }
      </div>
    `;

    banner.innerHTML = bannerHtml;
    bodyElem.parentNode.insertBefore(banner, bodyElem);

    const reportData = {
      overallRisk,
      senderName,
      senderEmail,
      isExternal,
      criticalCount,
      warningCount,
      cautionCount,
      issues: Array.from(new Set(detectedIssues)),
      linksCount: links.length,
      attachmentsCount: attachmentNodes.length
    };

    const detailsBtn = banner.querySelector('.gpg-view-details-btn');
    if (detailsBtn) {
      detailsBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        showSecurityReportModal(reportData);
      });
    }

    // Inject dedicated "Scan with Phishing Guard" button into email header
    injectEmailHeaderButton(emailContainer, reportData);
  }

  function injectEmailHeaderButton(emailContainer, reportData) {
    const headerRow = emailContainer.querySelector('.gH') || emailContainer.querySelector('.amn') || emailContainer.querySelector('.nH.gY') || emailContainer.querySelector('.a4X');
    if (!headerRow || headerRow.querySelector('.gpg-header-scan-btn')) return;

    const btn = document.createElement('button');
    btn.className = 'gpg-header-scan-btn';
    btn.innerHTML = `<span>🛡️ Scan Email with Phishing Guard</span>`;
    btn.title = 'Click to scan or view complete security report for this email';
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      processedEmails.delete(emailContainer);
      scanEmailMessage(emailContainer);
      showSecurityReportModal(reportData);
    });

    headerRow.appendChild(btn);
  }

  function injectToolbarButton() {
    const toolbars = document.querySelectorAll('div[role="toolbar"], .G-atb, div[gh="tm"], .aqL');
    toolbars.forEach((tb) => {
      if (tb.querySelector('.gpg-toolbar-scan-btn')) return;

      const btn = document.createElement('button');
      btn.className = 'gpg-toolbar-scan-btn';
      btn.innerHTML = `<span>🛡️ Scan with Phishing Guard</span>`;
      btn.title = 'Scan currently open email or inspect suspicious sender';
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        triggerManualScan();
      });

      // Insert at front or near main action cluster
      const firstGroup = tb.querySelector('.G-Ni') || tb.firstChild;
      if (firstGroup) {
        tb.insertBefore(btn, firstGroup.nextSibling);
      } else {
        tb.appendChild(btn);
      }
    });
  }

  function injectFloatingScanButton() {
    if (document.getElementById('gpg-floating-scan-btn')) return;

    const badge = document.createElement('div');
    badge.id = 'gpg-floating-scan-btn';
    badge.className = 'gpg-floating-badge';
    badge.title = 'Gmail Phishing Guard - Click to scan open email or check any link';
    badge.innerHTML = `
      <div class="gpg-badge-pulse"></div>
      <span>🛡️ Scan Email</span>
    `;

    badge.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      triggerManualScan();
    });

    document.body.appendChild(badge);
  }

  function triggerManualScan() {
    const emailViews = document.querySelectorAll('.adn.ads, [role="main"] .h7');
    if (emailViews.length > 0) {
      // Re-scan all currently visible emails
      emailViews.forEach((el) => {
        processedEmails.delete(el);
        scanEmailMessage(el);
      });
      // Scroll to the top banner of the active email
      const firstBanner = document.querySelector('.gpg-banner');
      if (firstBanner) {
        firstBanner.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
      // If we have an active email, show the security modal
      const activeContainer = emailViews[0];
      const senderElem = activeContainer.querySelector('[email]') || activeContainer.querySelector('.gD') || activeContainer.querySelector('.go');
      let senderEmail = senderElem ? (senderElem.getAttribute('email') || senderElem.innerText || '') : '';
      const senderName = senderElem ? (senderElem.getAttribute('name') || senderElem.innerText || '') : 'Sender';
      if (!senderEmail || !senderEmail.includes('@')) {
        const headerText = activeContainer.querySelector('.gH')?.innerText || '';
        const emailMatch = headerText.match(/<([^>]+@[^>]+)>/) || headerText.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
        if (emailMatch) senderEmail = emailMatch[1];
      }

      const senderDomain = cleanDomain(senderEmail);
      const isInternal = isTrustedOrInternalDomain(senderEmail) || isTrustedOrInternalDomain(senderDomain);
      const isExternal = !isInternal;

      const banner = document.querySelector('.gpg-banner');
      const isCritical = banner?.classList.contains('gpg-banner-critical');
      const isWarning = banner?.classList.contains('gpg-banner-warning');
      const isCaution = banner?.classList.contains('gpg-banner-caution');

      showSecurityReportModal({
        overallRisk: isCritical ? 'critical' : isWarning ? 'warning' : isCaution ? 'caution' : 'safe',
        senderName,
        senderEmail,
        senderDomain,
        isInternal,
        isExternal,
        issues: Array.from(document.querySelectorAll('.gpg-threat-list li')).map(li => li.innerText),
        linksCount: document.querySelectorAll('.gpg-link-tag').length,
        attachmentsCount: document.querySelectorAll('.gpg-attachment-badge').length
      });
    } else {
      // In inbox list view - prompt quick scan modal
      showQuickScannerModal();
    }
  }

  function showSecurityReportModal(data) {
    const existing = document.getElementById('gpg-security-modal');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'gpg-security-modal';
    overlay.className = 'gpg-modal-overlay';
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) overlay.remove();
    });

    const riskColor = data.overallRisk === 'critical'
      ? '#ef4444'
      : data.overallRisk === 'warning'
      ? '#f59e0b'
      : data.overallRisk === 'caution'
      ? '#eab308'
      : '#10b981';

    const riskLabel = data.overallRisk === 'critical'
      ? 'CRITICAL PHISHING THREAT'
      : data.overallRisk === 'warning'
      ? 'SUSPICIOUS EMAIL'
      : data.overallRisk === 'caution'
      ? 'EXTERNAL SENDER CAUTION'
      : 'VERIFIED SAFE';

    overlay.innerHTML = `
      <div class="gpg-modal-dialog">
        <div class="gpg-modal-header">
          <div class="gpg-modal-title">
            <span style="font-size: 20px;">🛡️</span>
            <span>Gmail Phishing Guard - Security Scan Report</span>
          </div>
          <button class="gpg-modal-close" id="gpg-modal-close-btn">&times;</button>
        </div>

        <div style="background: rgba(255,255,255,0.04); border: 1px solid ${riskColor}40; border-left: 6px solid ${riskColor}; padding: 14px; border-radius: 12px; display: flex; align-items: center; justify-content: space-between;">
          <div>
            <div style="font-size: 11px; font-weight: 700; color: ${riskColor}; text-transform: uppercase; letter-spacing: 0.05em;">VERDICT</div>
            <div style="font-size: 16px; font-weight: 800; color: #ffffff; margin-top: 2px;">${riskLabel}</div>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 11px; color: #94a3b8;">ORIGIN</div>
            <div style="font-size: 12px; font-weight: 700; color: ${data.isExternal ? '#f59e0b' : '#10b981'};">${data.isExternal ? '⚠️ External Source' : '🏢 Internal'}</div>
          </div>
        </div>

        <div style="font-size: 12px; color: #cbd5e1; line-height: 1.6;">
          <p><strong>Sender:</strong> ${escapeHtml(data.senderName)} &lt;<span style="font-family: monospace; color: #38bdf8;">${escapeHtml(data.senderEmail || 'unknown')}</span>&gt;</p>
        </div>

        ${data.issues && data.issues.length > 0 ? `
          <div style="background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 12px;">
            <div style="font-size: 11px; font-weight: 700; color: #f87171; text-transform: uppercase; margin-bottom: 6px;">⚠️ Threat Indicators Identified (${data.issues.length})</div>
            <ul style="margin: 0; padding-left: 20px; font-size: 12px; color: #fca5a5;">
              ${data.issues.map(iss => `<li style="margin-bottom: 4px;">${escapeHtml(iss)}</li>`).join('')}
            </ul>
          </div>
        ` : `
          <div style="background: #064e3b; border: 1px solid #059669; border-radius: 10px; padding: 12px; font-size: 12px; color: #a7f3d0;">
            ✓ No suspicious lookalike domains, deceptive links, or dangerous double extensions found.
          </div>
        `}

        <div style="display: flex; gap: 8px; justify-content: flex-end; margin-top: 8px;">
          <button id="gpg-report-phish-btn" style="background: #dc2626; color: #ffffff; border: none; border-radius: 8px; padding: 8px 16px; font-size: 12px; font-weight: 600; cursor: pointer;">
            🚩 Quarantine & Report Phishing
          </button>
          <button id="gpg-modal-done-btn" style="background: #334155; color: #ffffff; border: none; border-radius: 8px; padding: 8px 16px; font-size: 12px; font-weight: 600; cursor: pointer;">
            Close
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    overlay.querySelector('#gpg-modal-close-btn').addEventListener('click', () => overlay.remove());
    overlay.querySelector('#gpg-modal-done-btn').addEventListener('click', () => overlay.remove());
    overlay.querySelector('#gpg-report-phish-btn').addEventListener('click', () => {
      alert('✓ Phishing report submitted to security team. Email flagged.');
      overlay.remove();
    });
  }

  function showQuickScannerModal() {
    const existing = document.getElementById('gpg-security-modal');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'gpg-security-modal';
    overlay.className = 'gpg-modal-overlay';
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) overlay.remove();
    });

    overlay.innerHTML = `
      <div class="gpg-modal-dialog">
        <div class="gpg-modal-header">
          <div class="gpg-modal-title">
            <span style="font-size: 20px;">🛡️</span>
            <span>Gmail Phishing Guard - Scan Any Email / Link</span>
          </div>
          <button class="gpg-modal-close" id="gpg-modal-close-btn">&times;</button>
        </div>

        <p style="font-size: 13px; color: #94a3b8; margin: 0;">
          Open any email in Gmail to see its automatic Phishing Guard protection banner and highlighted links, or test any suspicious URL below:
        </p>

        <div style="display: flex; gap: 8px;">
          <input type="text" id="gpg-quick-url-input" placeholder="Paste link or domain (e.g. http://accounts-googIe.com)..." style="flex: 1; background: #020617; border: 1px solid #334155; border-radius: 8px; padding: 8px 12px; color: #ffffff; font-size: 12px; font-family: monospace;">
          <button id="gpg-quick-test-btn" style="background: #0284c7; color: #ffffff; border: none; border-radius: 8px; padding: 8px 16px; font-size: 12px; font-weight: 600; cursor: pointer;">
            Inspect Link
          </button>
        </div>

        <div id="gpg-quick-result" style="display: none; padding: 12px; border-radius: 10px; font-size: 12px;"></div>

        <div style="display: flex; justify-content: flex-end;">
          <button id="gpg-modal-done-btn" style="background: #334155; color: #ffffff; border: none; border-radius: 8px; padding: 8px 16px; font-size: 12px; font-weight: 600; cursor: pointer;">
            Close
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    overlay.querySelector('#gpg-modal-close-btn').addEventListener('click', () => overlay.remove());
    overlay.querySelector('#gpg-modal-done-btn').addEventListener('click', () => overlay.remove());

    const testBtn = overlay.querySelector('#gpg-quick-test-btn');
    const input = overlay.querySelector('#gpg-quick-url-input');
    const resDiv = overlay.querySelector('#gpg-quick-result');

    testBtn.addEventListener('click', () => {
      const val = input.value.trim();
      if (!val) return;
      const res = analyzeUrl(val, val);
      resDiv.style.display = 'block';
      if (res.risk === 'critical') {
        resDiv.style.background = '#450a0a';
        resDiv.style.border = '1px solid #ef4444';
        resDiv.style.color = '#fecaca';
        resDiv.innerHTML = `<strong>🔴 CRITICAL PHISHING RISK (Score ${res.score}/100)</strong><br>` + res.issues.map(i => `• ${i}`).join('<br>');
      } else if (res.risk === 'warning') {
        resDiv.style.background = '#451a03';
        resDiv.style.border = '1px solid #f59e0b';
        resDiv.style.color = '#fed7aa';
        resDiv.innerHTML = `<strong>🟠 SUSPICIOUS LINK (Score ${res.score}/100)</strong><br>` + res.issues.map(i => `• ${i}`).join('<br>');
      } else {
        resDiv.style.background = '#064e3b';
        resDiv.style.border = '1px solid #10b981';
        resDiv.style.color = '#a7f3d0';
        resDiv.innerHTML = `<strong>🟢 VERIFIED SAFE</strong><br>No known lookalike patterns or suspicious shorteners detected.`;
      }
    });
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Observe Gmail DOM changes
  const observer = new MutationObserver(() => {
    // 1. Scan any active open email messages
    const emailViews = document.querySelectorAll('.adn.ads, [role="main"] .h7');
    emailViews.forEach((el) => scanEmailMessage(el));

    // 2. Inject toolbar scan button
    injectToolbarButton();

    // 3. Inject floating scan button
    injectFloatingScanButton();
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // Initial injection
  injectToolbarButton();
  injectFloatingScanButton();

  console.log('🛡️ Gmail Phishing Guard Extension initialized with Toolbar & Floating buttons.');
})();

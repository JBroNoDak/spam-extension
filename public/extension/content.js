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
    interceptCriticalClicks: true,
  };

  // Load config from extension storage
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.sync) {
    chrome.storage.sync.get(['enabled', 'sensitivity', 'whitelist', 'interceptCriticalClicks'], (items) => {
      if (items) {
        config = { ...config, ...items };
      }
    });
  }

  // Track processed email elements to prevent re-processing
  const processedEmails = new WeakSet();

  function analyzeUrl(urlStr, textStr) {
    const issues = [];
    let risk = 'safe';
    let score = 0;

    try {
      const url = new URL(urlStr);
      const host = url.hostname.toLowerCase();
      const protocol = url.protocol.toLowerCase();

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
      const cleanHost = host.replace(/^www\./, '');
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
    const senderElem = emailContainer.querySelector('[email]') || emailContainer.querySelector('.gD');
    const senderEmail = senderElem ? (senderElem.getAttribute('email') || senderElem.innerText || '') : '';
    const senderName = senderElem ? (senderElem.getAttribute('name') || senderElem.innerText || '') : 'External Sender';

    // Determine if external sender
    const isExternal = senderEmail ? !senderEmail.endsWith('@company.com') : true;

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
    else if (cautionCount > 0 || isExternal) overallRisk = 'caution';

    // Inject top banner
    const banner = document.createElement('div');
    banner.className = `gpg-banner gpg-banner-${overallRisk}`;
    
    const badgeText = overallRisk === 'critical'
      ? '🔴 CRITICAL THREAT DETECTED'
      : overallRisk === 'warning'
      ? '🟠 SUSPICIOUS EMAIL'
      : overallRisk === 'caution'
      ? '🟡 EXTERNAL SENDER'
      : '🟢 VERIFIED SAFE';

    const bannerHtml = `
      <div class="gpg-banner-header">
        <span>🛡️ Gmail Phishing Guard: ${badgeText}</span>
        <span class="gpg-banner-badge gpg-banner-badge-${overallRisk}">${isExternal ? 'EXTERNAL SOURCE' : 'INTERNAL'}</span>
      </div>
      <div class="gpg-banner-body">
        ${
          overallRisk === 'critical'
            ? 'This email contains links or attachments exhibiting high-confidence phishing indicators. Do not enter credentials, download files, or respond.'
            : overallRisk === 'warning'
            ? 'Be cautious. This external email contains potential security anomalies such as obfuscated links or unusual attachments.'
            : isExternal
            ? 'This email originated from an external address. Verify the sender identity before clicking links or downloading files.'
            : 'All sender credentials, links, and attachments passed security inspection.'
        }
        ${
          detectedIssues.length > 0
            ? `<ul class="gpg-threat-list">${Array.from(new Set(detectedIssues)).slice(0, 3).map(i => `<li>${i}</li>`).join('')}</ul>`
            : ''
        }
      </div>
    `;

    banner.innerHTML = bannerHtml;
    bodyElem.parentNode.insertBefore(banner, bodyElem);
  }

  // Observe Gmail DOM changes
  const observer = new MutationObserver(() => {
    const emailViews = document.querySelectorAll('.adn.ads, [role="main"] .h7');
    emailViews.forEach((el) => scanEmailMessage(el));
  });

  observer.observe(document.body, { childList: true, subtree: true });

  console.log('🛡️ Gmail Phishing Guard Extension initialized.');
})();

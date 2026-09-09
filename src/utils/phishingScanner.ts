import { EmailMessage, EmailLink, EmailAttachment, EmailScanReport, RiskLevel } from '../types';

const POPULAR_BRANDS = [
  'google.com', 'microsoft.com', 'apple.com', 'paypal.com', 'chase.com',
  'bankofamerica.com', 'amazon.com', 'netflix.com', 'wellsfargo.com',
  'dropbox.com', 'docusign.com', 'slack.com', 'zoom.us', 'stripe.com'
];

const DANGEROUS_EXTENSIONS = [
  '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jse', '.wsf',
  '.hta', '.cpl', '.msi', '.msp', '.pif', '.com', '.iso', '.img',
  '.vhd', '.ps1', '.reg', '.iqy'
];

const SUSPICIOUS_EXTENSIONS = [
  '.zip', '.rar', '.7z', '.tar', '.gz', '.docm', '.xlsm', '.pptm',
  '.html', '.htm', '.svg'
];

export function cleanDomain(input: string): string {
  if (!input) return '';
  let str = String(input).trim().toLowerCase();
  str = str.replace(/^mailto:/, '');
  str = str.replace(/^https?:\/\//, '');
  if (str.includes('@')) {
    str = str.split('@').pop() || '';
  }
  str = str.split('/')[0].split(':')[0].split('?')[0];
  str = str.replace(/^www\./, '').replace(/^@+/, '').replace(/^\.+/, '');
  return str;
}

export function isDomainWhitelisted(domainOrEmail: string, whitelist: string[] = []): boolean {
  const target = cleanDomain(domainOrEmail);
  if (!target) return false;
  const list = whitelist.map(cleanDomain).filter(Boolean);
  for (const d of list) {
    if (target === d || target.endsWith('.' + d)) {
      return true;
    }
  }
  return false;
}

export function analyzeLink(urlStr: string, textStr: string = '', whitelist: string[] = []): EmailLink {
  const issues: string[] = [];
  let riskLevel: RiskLevel = 'safe';
  let score = 0;

  try {
    const parsed = new URL(urlStr.trim());
    const hostname = parsed.hostname.toLowerCase();
    const cleanHost = cleanDomain(hostname);
    const protocol = parsed.protocol.toLowerCase();

    // Whitelist check
    if (isDomainWhitelisted(cleanHost, whitelist)) {
      return {
        url: urlStr,
        text: textStr || urlStr,
        issues: [],
        riskLevel: 'safe',
        score: 0,
      };
    }

    // 1. Unencrypted HTTP
    if (protocol === 'http:') {
      issues.push('Unencrypted connection (HTTP instead of HTTPS)');
      score += 20;
      if (riskLevel === 'safe') riskLevel = 'caution';
    }

    // 2. IP Host
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    if (isIp) {
      issues.push('Direct numerical IP address used instead of legitimate domain');
      score += 55;
      riskLevel = 'critical';
    }

    // 3. Punycode / IDN
    if (hostname.startsWith('xn--')) {
      issues.push('Punycode / Internationalized domain detected (Homograph attack vector)');
      score += 45;
      riskLevel = 'critical';
    }

    // 4. Anchor text vs Href mismatch
    if (textStr && textStr.trim()) {
      const cleanText = textStr.trim();
      const domainMatch = cleanText.match(/https?:\/\/([a-zA-Z0-9.-]+)/i) || cleanText.match(/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      if (domainMatch) {
        const displayedDomain = domainMatch[1].toLowerCase().replace(/^www\./, '');
        const actualDomain = hostname.replace(/^www\./, '');
        if (displayedDomain !== actualDomain && !actualDomain.endsWith(`.${displayedDomain}`)) {
          issues.push(`Misleading Link: Displayed as "${displayedDomain}" but navigates to "${actualDomain}"`);
          score += 65;
          riskLevel = 'critical';
        }
      }
    }

    // 5. Lookalike brand imitation
    for (const brand of POPULAR_BRANDS) {
      const brandBase = brand.split('.')[0];
      if (cleanHost !== brand) {
        // e.g., 'googIe.com' or 'docus1gn' or 'accounts-google'
        if (cleanHost.includes(brandBase) || isOneDiff(cleanHost.split('.')[0], brandBase)) {
          issues.push(`Lookalike domain: "${cleanHost}" impersonates reputable domain "${brand}"`);
          score += 60;
          riskLevel = 'critical';
          break;
        }
      }
    }

    // 6. Shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'ow.ly', 'cutt.ly', 'rb.gy'];
    if (shorteners.includes(cleanHost)) {
      issues.push('URL shortener obscures the real final destination');
      score += 30;
      if (riskLevel !== 'critical') riskLevel = 'warning';
    }

    // 7. Suspicious keywords in path
    const path = parsed.pathname.toLowerCase();
    if (/(login|verify|signin|challenge|account|recovery|password|update-billing)/i.test(path)) {
      issues.push('Authentication or credential update keywords in link path');
      score += 20;
      if (riskLevel === 'safe') riskLevel = 'caution';
    }

  } catch {
    issues.push('Invalid or malformed URL syntax');
    score += 30;
    riskLevel = 'warning';
  }

  return {
    url: urlStr,
    text: textStr,
    issues,
    riskLevel,
    score: Math.min(100, score),
  };
}

function isOneDiff(a: string, b: string): boolean {
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

export function analyzeAttachment(att: EmailAttachment): EmailAttachment {
  const issues: string[] = [];
  let riskLevel: RiskLevel = 'safe';
  let score = 0;
  const lower = att.filename.toLowerCase();

  // Double extension
  const parts = lower.split('.');
  if (parts.length > 2) {
    const lastExt = `.${parts[parts.length - 1]}`;
    const secondLast = `.${parts[parts.length - 2]}`;
    if (DANGEROUS_EXTENSIONS.includes(lastExt) || (['.pdf', '.docx', '.xlsx', '.png'].includes(secondLast) && DANGEROUS_EXTENSIONS.includes(lastExt))) {
      issues.push(`Deceptive double extension detected ("${secondLast}${lastExt}") disguising executable code`);
      score += 85;
      riskLevel = 'critical';
    }
  }

  // Dangerous direct extensions
  if (riskLevel !== 'critical') {
    for (const ext of DANGEROUS_EXTENSIONS) {
      if (lower.endsWith(ext)) {
        issues.push(`Direct executable or script payload (${ext})`);
        score += 80;
        riskLevel = 'critical';
        break;
      }
    }
  }

  // Suspicious extensions
  if (riskLevel !== 'critical') {
    for (const ext of SUSPICIOUS_EXTENSIONS) {
      if (lower.endsWith(ext)) {
        if (ext === '.docm' || ext === '.xlsm') {
          issues.push(`Macro-enabled Microsoft Office document (${ext}) can run arbitrary VBA scripts`);
          score += 50;
          riskLevel = 'warning';
        } else if (ext === '.zip' || ext === '.rar' || ext === '.7z') {
          issues.push(`Compressed archive (${ext}) may contain hidden executable binaries`);
          score += 35;
          riskLevel = 'warning';
        } else {
          issues.push(`HTML/SVG payload format (${ext}) commonly used for credential harvesting`);
          score += 40;
          riskLevel = 'warning';
        }
        break;
      }
    }
  }

  // Lure keywords
  if (/(wire|invoice|urgent|receipt|remittance|statement|payment)/i.test(lower)) {
    issues.push('Financial lure terminology in attachment filename');
    score += 15;
    if (riskLevel === 'safe') riskLevel = 'caution';
  }

  return {
    ...att,
    issues,
    riskLevel,
    score: Math.min(100, score),
  };
}

export function scanEmailHeuristic(
  email: EmailMessage,
  whitelist: string[] = [],
  internalDomains: string[] = []
): EmailScanReport {
  const combinedTrusted = [...whitelist, ...internalDomains, 'acmecorp.com'];
  const senderDomain = cleanDomain(email.sender.domain || email.sender.email || '');
  const senderEmail = cleanDomain(email.sender.email || '');
  const isTrustedSender = isDomainWhitelisted(senderDomain, combinedTrusted) || isDomainWhitelisted(senderEmail, combinedTrusted);
  const effectiveIsExternal = isTrustedSender ? false : email.isExternal;

  // Extract links from HTML and bodyText
  const extractedLinks: EmailLink[] = [];
  const hrefRegex = /href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;
  let match;
  while ((match = hrefRegex.exec(email.bodyHtml)) !== null) {
    const url = match[1];
    const text = match[2].replace(/<[^>]+>/g, '').trim();
    if (!url.startsWith('mailto:') && !url.startsWith('#')) {
      extractedLinks.push(analyzeLink(url, text, combinedTrusted));
    }
  }

  // Fallback to plain text links if no HTML links
  if (extractedLinks.length === 0) {
    const rawUrlRegex = /(https?:\/\/[^\s<>"']+)/gi;
    let urlMatch;
    while ((urlMatch = rawUrlRegex.exec(email.bodyText)) !== null) {
      extractedLinks.push(analyzeLink(urlMatch[1], urlMatch[1], combinedTrusted));
    }
  }

  const analyzedAttachments = (email.attachments || []).map(analyzeAttachment);

  let score = 0;
  const heuristicSignals: string[] = [];

  if (effectiveIsExternal) {
    heuristicSignals.push('Email originates from an external organization');
    score += 10;
  } else if (isTrustedSender) {
    heuristicSignals.push(`Sender domain verified as trusted/internal organization (${senderDomain || 'organization'})`);
  }

  // Check display name impersonation
  const senderName = email.sender.name || '';
  for (const brand of POPULAR_BRANDS) {
    const brandName = brand.split('.')[0];
    if (new RegExp(`\\b${brandName}\\b`, 'i').test(senderName) && !senderDomain.includes(brandName) && !isTrustedSender) {
      heuristicSignals.push(`Sender display name "${senderName}" claims association with ${brandName}, but uses external domain "${senderDomain}"`);
      score += 50;
    }
  }

  // Executive impersonation from free webmail
  const freeWebmail = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com'];
  if (freeWebmail.includes(senderDomain) && /(ceo|cfo|executive|payroll|hr|wire|transfer)/i.test(senderName + ' ' + email.subject)) {
    heuristicSignals.push(`Executive or financial authority role claim sent from free public webmail (${senderDomain})`);
    score += 45;
  }

  // Auth header checks
  if (email.headers?.spf === 'fail' || email.headers?.dkim === 'fail' || email.headers?.dmarc === 'fail') {
    heuristicSignals.push('Email authentication validation failed (SPF/DKIM/DMARC mismatch)');
    score += 40;
  }

  const maxLinkScore = extractedLinks.reduce((max, l) => Math.max(max, l.score || 0), 0);
  const maxAttScore = analyzedAttachments.reduce((max, a) => Math.max(max, a.score || 0), 0);

  score += Math.round(maxLinkScore * 0.45);
  score += Math.round(maxAttScore * 0.45);

  const content = `${email.subject} ${email.bodyText}`.toLowerCase();
  if (/(immediate action|suspended within 24|account closure|wire transfer|gift card|unauthorized login|verify your password|tax refund|crypto)/i.test(content)) {
    heuristicSignals.push('High-pressure urgency or financial threat triggers detected');
    score += 25;
  }

  const overallScore = Math.min(100, Math.max(0, score));

  let overallRiskLevel: RiskLevel = 'safe';
  if (overallScore >= 70 || maxLinkScore >= 70 || maxAttScore >= 70) {
    overallRiskLevel = 'critical';
  } else if (overallScore >= 45 || maxLinkScore >= 45 || maxAttScore >= 45) {
    overallRiskLevel = 'warning';
  } else if (overallScore >= 20 || effectiveIsExternal) {
    overallRiskLevel = 'caution';
  } else {
    overallRiskLevel = 'safe';
  }

  return {
    overallRiskLevel,
    overallScore,
    isExternal: effectiveIsExternal,
    heuristicSignals,
    links: extractedLinks,
    attachments: analyzedAttachments,
    timestamp: new Date().toISOString(),
  };
}

export async function requestDeepAiScan(email: EmailMessage): Promise<EmailScanReport> {
  const localReport = scanEmailHeuristic(email);

  try {
    const response = await fetch('/api/scan-email', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        sender: email.sender,
        recipient: email.recipient,
        subject: email.subject,
        bodyText: email.bodyText,
        bodyHtml: email.bodyHtml,
        links: localReport.links,
        attachments: localReport.attachments,
        headers: email.headers,
        isExternal: email.isExternal,
      }),
    });

    if (response.ok) {
      const data = await response.json();
      return {
        ...localReport,
        ...data,
      };
    }
  } catch (err) {
    console.warn('API threat scan request failed, using client heuristic report:', err);
  }

  return localReport;
}

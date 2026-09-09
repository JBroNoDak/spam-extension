import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';
import { createServer as createViteServer } from 'vite';

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '10mb' }));

// Lazy initialization of Gemini client
let genAIClient: GoogleGenAI | null = null;
function getGenAI(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return null;
  }
  if (!genAIClient) {
    genAIClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return genAIClient;
}

// Popular domains monitored for typosquatting / homograph attacks
const POPULAR_DOMAINS = [
  'google.com',
  'gmail.com',
  'microsoft.com',
  'office.com',
  'live.com',
  'outlook.com',
  'apple.com',
  'icloud.com',
  'amazon.com',
  'paypal.com',
  'chase.com',
  'wellsfargo.com',
  'bankofamerica.com',
  'netflix.com',
  'dropbox.com',
  'github.com',
  'docu-sign.com',
  'docusign.com',
  'slack.com',
  'zoom.us',
  'adobe.com',
  'stripe.com',
];

// Dangerous attachment extensions
const DANGEROUS_EXTENSIONS = [
  '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jse', '.wsf',
  '.hta', '.cpl', '.msi', '.msp', '.pif', '.com', '.gadget',
  '.jar', '.iso', '.img', '.vhd', '.vhdx', '.ps1', '.reg',
  '.iqy', '.xll'
];

const SUSPICIOUS_EXTENSIONS = [
  '.zip', '.rar', '.7z', '.tar', '.gz', '.docm', '.xlsm', '.pptm',
  '.dotm', '.xltm', '.svg', '.html', '.htm', '.url'
];

function analyzeLinkHeuristic(urlStr: string, textStr: string) {
  const issues: string[] = [];
  let riskLevel: 'safe' | 'caution' | 'warning' | 'critical' = 'safe';
  let score = 0;

  try {
    const parsed = new URL(urlStr.trim());
    const hostname = parsed.hostname.toLowerCase();
    const protocol = parsed.protocol.toLowerCase();

    // Insecure HTTP
    if (protocol === 'http:') {
      issues.push('Unencrypted connection (HTTP instead of HTTPS)');
      score += 15;
      if (riskLevel === 'safe') riskLevel = 'caution';
    }

    // IP address host
    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    if (isIp) {
      issues.push('Target URL uses raw numerical IP address instead of domain name');
      score += 45;
      riskLevel = 'critical';
    }

    // Punycode / IDN
    if (hostname.startsWith('xn--')) {
      issues.push('Punycode / Internationalized domain detected (potential homograph impersonation)');
      score += 40;
      riskLevel = 'critical';
    }

    // Text vs Href mismatch
    if (textStr && textStr.trim().length > 0) {
      const cleanText = textStr.trim();
      const textHasDomain = cleanText.match(/https?:\/\/([a-zA-Z0-9.-]+)/i) || cleanText.match(/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      if (textHasDomain) {
        const displayedDomain = textHasDomain[1].toLowerCase().replace(/^www\./, '');
        const actualDomain = hostname.replace(/^www\./, '');
        if (displayedDomain !== actualDomain && !actualDomain.endsWith(`.${displayedDomain}`)) {
          issues.push(`Misleading Link: Displayed as "${displayedDomain}" but navigates to "${actualDomain}"`);
          score += 55;
          riskLevel = 'critical';
        }
      }
    }

    // Typosquatting checks against popular brands
    for (const popular of POPULAR_DOMAINS) {
      const cleanHost = hostname.replace(/^www\./, '');
      if (cleanHost !== popular) {
        // Check for character substitution like 'googIe.com' or 'micros0ft.com'
        const baseName = popular.split('.')[0];
        if (cleanHost.includes(baseName) || levenshteinDistance(cleanHost.split('.')[0], baseName) === 1) {
          issues.push(`Lookalike domain detected: "${cleanHost}" mimics legitimate "${popular}"`);
          score += 60;
          riskLevel = 'critical';
          break;
        }
      }
    }

    // Shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'ow.ly', 'buff.ly', 'cutt.ly', 'rb.gy'];
    if (shorteners.includes(hostname.replace(/^www\./, ''))) {
      issues.push('URL shortener obscures the real final destination');
      score += 25;
      if (riskLevel !== 'critical') riskLevel = 'warning';
    }

    // Suspicious path triggers
    const pathLower = parsed.pathname.toLowerCase();
    if (pathLower.includes('login') || pathLower.includes('verify') || pathLower.includes('password') || pathLower.includes('signin') || pathLower.includes('account')) {
      issues.push('Authentication or credential update keywords in link path');
      score += 20;
      if (riskLevel === 'safe') riskLevel = 'caution';
    }

  } catch {
    issues.push('Malformed or invalid URL structure');
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

function analyzeAttachmentHeuristic(attachment: { filename: string; size?: number; mimeType?: string }) {
  const filename = attachment.filename.toLowerCase();
  const issues: string[] = [];
  let riskLevel: 'safe' | 'caution' | 'warning' | 'critical' = 'safe';
  let score = 0;

  // Double extension detection (e.g., invoice.pdf.exe)
  const parts = filename.split('.');
  if (parts.length > 2) {
    const lastExt = `.${parts[parts.length - 1]}`;
    const secondLastExt = `.${parts[parts.length - 2]}`;
    if (DANGEROUS_EXTENSIONS.includes(lastExt) || (['.pdf', '.docx', '.xlsx', '.jpg', '.png'].includes(secondLastExt) && DANGEROUS_EXTENSIONS.includes(lastExt))) {
      issues.push(`Deceptive double extension detected ("${secondLastExt}${lastExt}") disguising executable code`);
      score += 75;
      riskLevel = 'critical';
    }
  }

  // Dangerous direct extensions
  for (const ext of DANGEROUS_EXTENSIONS) {
    if (filename.endsWith(ext)) {
      issues.push(`Direct executable or script payload (${ext})`);
      score += 70;
      riskLevel = 'critical';
      break;
    }
  }

  // Suspicious extensions (macro enabled or archives)
  if (riskLevel !== 'critical') {
    for (const ext of SUSPICIOUS_EXTENSIONS) {
      if (filename.endsWith(ext)) {
        if (ext === '.docm' || ext === '.xlsm') {
          issues.push(`Macro-enabled Microsoft Office document (${ext}) can execute arbitrary code`);
          score += 45;
          riskLevel = 'warning';
        } else if (ext === '.zip' || ext === '.rar' || ext === '.7z') {
          issues.push(`Compressed archive (${ext}) may contain obscured or encrypted binaries`);
          score += 25;
          riskLevel = 'warning';
        } else if (ext === '.html' || ext === '.htm' || ext === '.svg') {
          issues.push(`HTML or SVG attachment commonly leveraged for offline phishing forms`);
          score += 35;
          riskLevel = 'warning';
        }
        break;
      }
    }
  }

  // Suspicious filenames
  if (/(urgent|invoice|wire|receipt|remittance|payment|swift|payroll|statement)/i.test(filename)) {
    issues.push('Financial or urgency lure keywords in attachment filename');
    score += 15;
    if (riskLevel === 'safe') riskLevel = 'caution';
  }

  return {
    filename: attachment.filename,
    size: attachment.size,
    mimeType: attachment.mimeType,
    issues,
    riskLevel,
    score: Math.min(100, score),
  };
}

function levenshteinDistance(a: string, b: string): number {
  const matrix = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }
  return matrix[a.length][b.length];
}

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    aiAvailable: Boolean(process.env.GEMINI_API_KEY),
  });
});

// Single URL check endpoint
app.post('/api/check-url', (req, res) => {
  const { url, text } = req.body;
  if (!url) {
    res.status(400).json({ error: 'URL parameter is required' });
    return;
  }
  const result = analyzeLinkHeuristic(url, text || '');
  res.json(result);
});

// Email Scan endpoint (Deterministic Heuristics + Gemini 3.8 Flash AI)
app.post('/api/scan-email', async (req, res) => {
  try {
    const {
      sender,
      recipient,
      subject,
      bodyText,
      bodyHtml,
      links = [],
      attachments = [],
      headers = {},
      isExternal = true,
    } = req.body;

    const analyzedLinks = (links as Array<{ url: string; text?: string }>).map((l) =>
      analyzeLinkHeuristic(l.url, l.text || '')
    );

    const analyzedAttachments = (attachments as Array<{ filename: string; size?: number; mimeType?: string }>).map((a) =>
      analyzeAttachmentHeuristic(a)
    );

    // Heuristic assessment
    let heuristicScore = 0;
    const heuristicSignals: string[] = [];

    if (isExternal) {
      heuristicSignals.push('Email originates from an external organization');
      heuristicScore += 10;
    }

    // Sender spoofing / display name tricks
    const senderEmail = (sender?.email || '').toLowerCase();
    const senderName = sender?.name || '';
    const senderDomain = senderEmail.split('@')[1] || '';

    // Check if sender display name mimics major company but domain doesn't match
    for (const pop of POPULAR_DOMAINS) {
      const brand = pop.split('.')[0];
      if (new RegExp(`\\b${brand}\\b`, 'i').test(senderName) && !senderDomain.includes(brand)) {
        heuristicSignals.push(`Display name impersonation: Sender name "${senderName}" claims association with ${brand}, but email is from external domain "${senderDomain}"`);
        heuristicScore += 50;
      }
    }

    // Free webmail used for corporate/financial matters
    const freeWebmail = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'protonmail.com'];
    if (freeWebmail.includes(senderDomain) && /(ceo|cfo|executive|payroll|hr|finance|billing|support)/i.test(senderName + ' ' + (subject || ''))) {
      heuristicSignals.push(`Executive or corporate role impersonation from generic public webmail (${senderDomain})`);
      heuristicScore += 45;
    }

    // Authentication headers check
    if (headers?.spf === 'fail' || headers?.dkim === 'fail' || headers?.dmarc === 'fail') {
      heuristicSignals.push('Email authentication failed (SPF/DKIM/DMARC mismatch)');
      heuristicScore += 40;
    }

    // Highest link risk
    const maxLinkScore = analyzedLinks.reduce((max, l) => Math.max(max, l.score), 0);
    const maxAttachmentScore = analyzedAttachments.reduce((max, a) => Math.max(max, a.score), 0);

    heuristicScore += Math.round(maxLinkScore * 0.4);
    heuristicScore += Math.round(maxAttachmentScore * 0.4);

    // Urgency and social engineering keywords
    const fullContent = `${subject || ''} ${bodyText || ''}`.toLowerCase();
    if (/(urgent|immediate action|suspended within 24|account closure|wire transfer|gift card|unauthorized login|verify your password|tax refund)/i.test(fullContent)) {
      heuristicSignals.push('High-pressure urgency or coercive financial/credential lure keywords detected');
      heuristicScore += 25;
    }

    heuristicScore = Math.min(100, Math.max(0, heuristicScore));

    // Optional AI Analysis using Gemini 3.8 Flash
    let aiAnalysis: {
      isPhishing: boolean;
      confidence: number;
      threatCategory: string;
      reasoning: string;
      socialEngineeringTactics: string[];
      recommendations: string[];
    } | null = null;

    const genAI = getGenAI();
    if (genAI) {
      try {
        const prompt = `You are a cybersecurity email threat analyst embedded in a Chrome Extension for Gmail.
Analyze the following email from an external sender for phishing, brand impersonation, business email compromise (BEC), credential harvesting, and malware delivery.

EMAIL DETAILS:
- Sender Name: ${sender?.name || 'Unknown'}
- Sender Email: ${sender?.email || 'Unknown'}
- Is External Source: ${isExternal ? 'YES' : 'NO'}
- Subject: ${subject || '(No Subject)'}
- Extracted Links (${analyzedLinks.length}): ${analyzedLinks.map((l) => `${l.url} [Displayed text: "${l.text}"]`).join(', ') || 'None'}
- Attachments (${analyzedAttachments.length}): ${analyzedAttachments.map((a) => a.filename).join(', ') || 'None'}
- Header Flags: ${JSON.stringify(headers || {})}
- Email Body Excerpt:
${(bodyText || '').slice(0, 2000)}

Respond strictly in valid JSON format matching this schema:
{
  "isPhishing": boolean,
  "threatScore": number (0 to 100),
  "threatCategory": "Safe" | "Credential Harvesting" | "Business Email Compromise (BEC)" | "Malware / Ransomware" | "Brand Impersonation" | "Financial / Invoice Fraud" | "Suspicious External Communication",
  "reasoning": "Clear concise explanation for the user",
  "socialEngineeringTactics": ["list", "of", "detected", "tactics"],
  "recommendations": ["step 1", "step 2"]
}`;

        const response = await genAI.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: prompt,
          config: {
            responseMimeType: 'application/json',
          },
        });

        if (response.text) {
          const parsed = JSON.parse(response.text);
          aiAnalysis = {
            isPhishing: Boolean(parsed.isPhishing),
            confidence: typeof parsed.threatScore === 'number' ? parsed.threatScore : (parsed.isPhishing ? 85 : 10),
            threatCategory: parsed.threatCategory || 'Suspicious External Communication',
            reasoning: parsed.reasoning || 'AI analysis detected anomaly in email content.',
            socialEngineeringTactics: Array.isArray(parsed.socialEngineeringTactics) ? parsed.socialEngineeringTactics : [],
            recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations : ['Do not click suspicious links or open unverified attachments.'],
          };
        }
      } catch (geminiErr) {
        console.error('Gemini threat analysis encountered an issue, falling back to heuristics:', geminiErr);
      }
    }

    // Final consolidated score
    let overallScore = heuristicScore;
    if (aiAnalysis) {
      // Blend AI and heuristic
      overallScore = Math.round(heuristicScore * 0.45 + aiAnalysis.confidence * 0.55);
    }

    let overallRiskLevel: 'safe' | 'caution' | 'warning' | 'critical' = 'safe';
    if (overallScore >= 70 || maxLinkScore >= 70 || maxAttachmentScore >= 70) {
      overallRiskLevel = 'critical';
    } else if (overallScore >= 45 || maxLinkScore >= 45 || maxAttachmentScore >= 45) {
      overallRiskLevel = 'warning';
    } else if (overallScore >= 20 || isExternal) {
      overallRiskLevel = 'caution';
    } else {
      overallRiskLevel = 'safe';
    }

    res.json({
      overallRiskLevel,
      overallScore,
      isExternal: Boolean(isExternal),
      sender,
      subject,
      heuristicSignals,
      links: analyzedLinks,
      attachments: analyzedAttachments,
      aiAnalysis,
      timestamp: new Date().toISOString(),
    });
  } catch (error: any) {
    console.error('Error during email scan:', error);
    res.status(500).json({ error: error?.message || 'Failed to scan email' });
  }
});

// Vite middleware & static serving
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Gmail Phishing Shield Extension Server running on port ${PORT}`);
  });
}

startServer();

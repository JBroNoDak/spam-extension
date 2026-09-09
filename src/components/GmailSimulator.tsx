import React, { useState, useMemo } from 'react';
import {
  Inbox,
  Star,
  Send,
  FileText,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Search,
  MoreVertical,
  ArrowLeft,
  Paperclip,
  Clock,
  Sparkles,
  ExternalLink,
  Shield,
  FileCode,
  FileSpreadsheet,
  FileArchive,
  CheckCircle2,
  AlertCircle,
  FileQuestion,
  Lock,
  Flag,
  Download,
  X,
  Check,
} from 'lucide-react';
import { EmailMessage, EmailScanReport, EmailLink, EmailAttachment, RiskLevel } from '../types';
import { SecurityBanner } from './SecurityBanner';
import { LinkInspectorModal } from './LinkInspectorModal';
import { scanEmailHeuristic, requestDeepAiScan } from '../utils/phishingScanner';

interface GmailSimulatorProps {
  emails: EmailMessage[];
  onOpenCustomScanner: () => void;
  onOpenExtensionPackage: () => void;
}

export const GmailSimulator: React.FC<GmailSimulatorProps> = ({
  emails,
  onOpenCustomScanner,
  onOpenExtensionPackage,
}) => {
  const [selectedEmailId, setSelectedEmailId] = useState<string>(emails[0].id);
  const [activeFolder, setActiveFolder] = useState<'inbox' | 'quarantine' | 'starred'>('inbox');
  const [searchQuery, setSearchQuery] = useState('');
  const [inspectedLink, setInspectedLink] = useState<EmailLink | null>(null);
  const [isDeepScanning, setIsDeepScanning] = useState(false);
  const [reportsCache, setReportsCache] = useState<Record<string, EmailScanReport>>({});
  const [reportedEmails, setReportedEmails] = useState<Record<string, boolean>>({});
  const [showReportModal, setShowReportModal] = useState(false);
  const [scanNotification, setScanNotification] = useState<string | null>(null);

  // Compute or retrieve scan report for current selected email
  const currentEmail = useMemo(() => {
    return emails.find((e) => e.id === selectedEmailId) || emails[0];
  }, [emails, selectedEmailId]);

  const currentReport = useMemo(() => {
    if (reportsCache[currentEmail.id]) {
      return reportsCache[currentEmail.id];
    }
    const report = scanEmailHeuristic(currentEmail);
    return report;
  }, [currentEmail, reportsCache]);

  // Pre-calculate risk badges for email list view
  const emailRiskMap = useMemo(() => {
    const map: Record<string, EmailScanReport> = {};
    emails.forEach((email) => {
      map[email.id] = reportsCache[email.id] || scanEmailHeuristic(email);
    });
    return map;
  }, [emails, reportsCache]);

  const handleTriggerScan = async (useAi: boolean = false, targetEmail?: EmailMessage) => {
    const target = targetEmail || currentEmail;
    setIsDeepScanning(true);
    setScanNotification(`Scanning "${target.subject.slice(0, 30)}..."`);
    try {
      let updatedReport: EmailScanReport;
      if (useAi) {
        updatedReport = await requestDeepAiScan(target);
      } else {
        // Quick artificial heuristic latency for realistic feedback
        await new Promise((r) => setTimeout(r, 400));
        updatedReport = scanEmailHeuristic(target);
      }
      setReportsCache((prev) => ({
        ...prev,
        [target.id]: updatedReport,
      }));
      setShowReportModal(true);
      setScanNotification(`✓ Scan complete: ${updatedReport.overallRiskLevel.toUpperCase()} (Score: ${updatedReport.overallScore}/100)`);
      setTimeout(() => setScanNotification(null), 4000);
    } finally {
      setIsDeepScanning(false);
    }
  };

  const handleDeepScan = async () => {
    await handleTriggerScan(true);
  };

  const handleReportPhishing = () => {
    setReportedEmails((prev) => ({
      ...prev,
      [currentEmail.id]: true,
    }));
  };

  // Filter emails based on folder and search query
  const filteredEmails = useMemo(() => {
    return emails.filter((email) => {
      const report = emailRiskMap[email.id];
      if (activeFolder === 'quarantine' && report?.overallRiskLevel !== 'critical') {
        return false;
      }
      if (activeFolder === 'starred' && !email.isStarred) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          email.subject.toLowerCase().includes(q) ||
          email.sender.name.toLowerCase().includes(q) ||
          email.sender.email.toLowerCase().includes(q) ||
          email.snippet.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [emails, activeFolder, searchQuery, emailRiskMap]);

  // Transform email HTML to inject interactive link inspectors matching Chrome Extension content script
  const processedBodyHtml = useMemo(() => {
    let html = currentEmail.bodyHtml;

    // Map each link to its analyzed counterpart
    currentReport.links.forEach((l) => {
      const escapedUrl = l.url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const linkRegex = new RegExp(`<a\\s+([^>]*?)href=["']${escapedUrl}["']([^>]*?)>(.*?)<\\/a>`, 'gi');

      const riskClass =
        l.riskLevel === 'critical'
          ? 'bg-red-500/20 text-red-300 border-b-2 border-dashed border-red-500 px-1 py-0.5 rounded font-medium'
          : l.riskLevel === 'warning'
          ? 'bg-amber-500/20 text-amber-300 border-b-2 border-dashed border-amber-500 px-1 py-0.5 rounded font-medium'
          : l.riskLevel === 'caution'
          ? 'bg-yellow-500/20 text-yellow-300 border-b border-dashed border-yellow-500 px-1 py-0.5 rounded'
          : 'text-sky-400 underline';

      const tagText =
        l.riskLevel === 'critical'
          ? '🔴 PHISHING THREAT'
          : l.riskLevel === 'warning'
          ? '🟠 SUSPICIOUS'
          : l.riskLevel === 'caution'
          ? '🟡 CAUTION'
          : '🟢 SAFE';

      const tagBadge =
        l.riskLevel !== 'safe'
          ? `<span class="inline-block text-[10px] font-bold px-1.5 py-0.2 mx-1 rounded ${
              l.riskLevel === 'critical'
                ? 'bg-red-600 text-white'
                : l.riskLevel === 'warning'
                ? 'bg-amber-600 text-white'
                : 'bg-yellow-600 text-white'
            }">${tagText}</span>`
          : '';

      html = html.replace(
        linkRegex,
        `<span class="gpg-link-wrapper cursor-pointer inline-flex items-center flex-wrap" data-url="${l.url}" data-text="${l.text || ''}">
          <span class="${riskClass}">$3</span>
          ${tagBadge}
        </span>`
      );
    });

    return html;
  }, [currentEmail, currentReport]);

  const handleBodyClick = (e: React.MouseEvent<HTMLDivElement>) => {
    const target = (e.target as HTMLElement).closest('.gpg-link-wrapper');
    if (target) {
      e.preventDefault();
      const url = target.getAttribute('data-url');
      const text = target.getAttribute('data-text') || '';
      if (url) {
        const found = currentReport.links.find((l) => l.url === url) || {
          url,
          text,
          riskLevel: 'caution' as RiskLevel,
          issues: ['Unverified destination clicked'],
        };
        setInspectedLink(found);
      }
    }
  };

  const getAttachmentIcon = (filename: string) => {
    const ext = filename.split('.').pop()?.toLowerCase();
    if (['exe', 'scr', 'bat', 'vbs', 'iso'].includes(ext || '')) {
      return <FileCode className="w-4 h-4 text-red-400" />;
    }
    if (['zip', 'rar', '7z'].includes(ext || '')) {
      return <FileArchive className="w-4 h-4 text-amber-400" />;
    }
    if (['docm', 'xlsm', 'xlsx'].includes(ext || '')) {
      return <FileSpreadsheet className="w-4 h-4 text-amber-400" />;
    }
    return <FileText className="w-4 h-4 text-slate-400" />;
  };

  return (
    <div className="flex flex-col h-full bg-slate-950 text-slate-100 overflow-hidden select-none">
      {/* Top Gmail App Bar */}
      <header className="h-14 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between px-4 gap-4 flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-red-600 flex items-center justify-center font-bold text-white text-xs shadow-sm">
              M
            </div>
            <span className="font-semibold text-base tracking-tight text-white hidden sm:inline">
              Gmail
            </span>
          </div>

          {/* Extension Injected Status Pill */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-950/60 border border-emerald-500/40 text-emerald-300 text-xs">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
            <span className="font-medium hidden md:inline">Gmail Phishing Guard Injected & Active</span>
            <span className="font-medium md:hidden">Guard Active</span>
          </div>
        </div>

        {/* Gmail Search Bar */}
        <div className="flex-1 max-w-xl mx-2">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search in mail or check sender domain..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 bg-slate-950/60 border border-slate-700/80 rounded-full text-xs text-slate-100 placeholder-slate-400 focus:outline-none focus:border-sky-500 transition-colors"
            />
          </div>
        </div>

        {/* Quick Toolbar Actions */}
        <div className="flex items-center gap-2">
          <button
            id="top-bar-scan-email-btn"
            onClick={() => handleTriggerScan(false)}
            disabled={isDeepScanning}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-sky-600 to-indigo-600 hover:from-sky-500 hover:to-indigo-500 text-white font-bold text-xs shadow-md shadow-sky-500/20 transition-all cursor-pointer disabled:opacity-50"
            title="Scan this email for phishing, deceptive links, and attachments"
          >
            <Shield className="w-4 h-4" />
            <span>{isDeepScanning ? 'Scanning...' : 'Scan Email with Guard'}</span>
          </button>

          <button
            id="open-custom-scanner-header-btn"
            onClick={onOpenCustomScanner}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors cursor-pointer"
            title="Test any custom email or link"
          >
            <Sparkles className="w-3.5 h-3.5 text-sky-400" />
            <span className="hidden sm:inline">Testbench</span>
          </button>

          <button
            id="download-extension-header-btn"
            onClick={onOpenExtensionPackage}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors cursor-pointer"
            title="Download Chrome Extension package"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            <span className="hidden sm:inline">Get Extension</span>
          </button>
        </div>
      </header>

      {/* Main Mailbox Workspace */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Navigation Sidebar */}
        <aside className="w-48 lg:w-56 border-r border-slate-800 bg-slate-900/50 flex flex-col justify-between p-3 flex-shrink-0">
          <div className="space-y-1">
            <button
              id="compose-btn"
              onClick={onOpenCustomScanner}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 mb-4 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold shadow-sm transition-colors cursor-pointer"
            >
              <Sparkles className="w-4 h-4 text-sky-400" />
              <span>Scan Any Email</span>
            </button>

            <nav className="space-y-0.5 text-xs">
              <button
                onClick={() => setActiveFolder('inbox')}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg transition-colors cursor-pointer ${
                  activeFolder === 'inbox'
                    ? 'bg-sky-950/60 text-sky-300 font-semibold border-l-2 border-sky-400'
                    : 'text-slate-300 hover:bg-slate-800/60'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Inbox className="w-4 h-4" />
                  <span>Inbox</span>
                </div>
                <span className="text-[11px] px-1.5 py-0.5 rounded-full bg-slate-800 text-slate-400 font-mono">
                  {emails.length}
                </span>
              </button>

              <button
                onClick={() => setActiveFolder('quarantine')}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg transition-colors cursor-pointer ${
                  activeFolder === 'quarantine'
                    ? 'bg-red-950/60 text-red-300 font-semibold border-l-2 border-red-400'
                    : 'text-slate-300 hover:bg-slate-800/60'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                  <span>Quarantine</span>
                </div>
                <span className="text-[11px] px-1.5 py-0.5 rounded-full bg-red-950 text-red-400 font-bold font-mono">
                  {emails.filter((e) => emailRiskMap[e.id]?.overallRiskLevel === 'critical').length}
                </span>
              </button>

              <button
                onClick={() => setActiveFolder('starred')}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg transition-colors cursor-pointer ${
                  activeFolder === 'starred'
                    ? 'bg-amber-950/60 text-amber-300 font-semibold border-l-2 border-amber-400'
                    : 'text-slate-300 hover:bg-slate-800/60'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Star className="w-4 h-4 text-amber-400" />
                  <span>Starred</span>
                </div>
              </button>
            </nav>

            <div className="pt-4 mt-4 border-t border-slate-800">
              <div className="text-[10px] uppercase font-bold text-slate-400 tracking-wider px-3 mb-2">
                Threat Matrix Legend
              </div>
              <div className="space-y-1.5 px-3 text-[11px]">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span>
                  <span className="text-slate-300">Critical Phishing</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
                  <span className="text-slate-300">Suspicious Anomaly</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-yellow-500"></span>
                  <span className="text-slate-300">External Caution</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                  <span className="text-slate-300">Verified Safe</span>
                </div>
              </div>
            </div>
          </div>

          {/* Bottom Extension Telemetry Card */}
          <div className="bg-slate-950/80 p-2.5 rounded-xl border border-slate-800 text-[11px] space-y-1.5">
            <div className="flex items-center justify-between text-slate-400">
              <span>Extension Engine:</span>
              <span className="text-emerald-400 font-mono font-semibold">v1.0.0 MV3</span>
            </div>
            <div className="flex items-center justify-between text-slate-400">
              <span>External Filter:</span>
              <span className="text-sky-400 font-mono">Strict</span>
            </div>
            <div className="text-[10px] text-slate-400 border-t border-slate-800 pt-1">
              Active DOM mutation monitor hooked to Gmail
            </div>
          </div>
        </aside>

        {/* Email List Column */}
        <div className="w-72 lg:w-80 border-r border-slate-800 bg-slate-900/30 flex flex-col flex-shrink-0 overflow-y-auto">
          <div className="p-2.5 border-b border-slate-800 text-xs font-semibold text-slate-400 flex items-center justify-between">
            <span>
              {activeFolder.toUpperCase()} ({filteredEmails.length})
            </span>
            <button
              onClick={() => handleTriggerScan(false)}
              className="text-[11px] text-sky-400 hover:text-sky-300 font-semibold flex items-center gap-1 cursor-pointer"
              title="Scan selected email immediately"
            >
              <Shield className="w-3 h-3" />
              <span>Scan Current</span>
            </button>
          </div>

          <div className="divide-y divide-slate-800/60">
            {filteredEmails.map((email) => {
              const rep = emailRiskMap[email.id];
              const isSelected = email.id === selectedEmailId;

              const pillStyle =
                rep?.overallRiskLevel === 'critical'
                  ? 'bg-red-500/20 text-red-300 border-red-500/40'
                  : rep?.overallRiskLevel === 'warning'
                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                  : rep?.overallRiskLevel === 'caution'
                  ? 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40'
                  : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';

              return (
                <div
                  key={email.id}
                  onClick={() => setSelectedEmailId(email.id)}
                  className={`p-3 cursor-pointer transition-colors relative ${
                    isSelected ? 'bg-slate-800/90 border-l-3 border-sky-400' : 'hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="font-semibold text-xs text-slate-200 truncate max-w-[170px]">
                      {email.sender.name}
                    </span>
                    <span className="text-[10px] text-slate-400 flex-shrink-0">{email.date.split(' ')[0]}</span>
                  </div>

                  <div className="text-xs text-slate-300 font-medium truncate mb-1">
                    {email.subject}
                  </div>

                  <p className="text-[11px] text-slate-400 line-clamp-2 leading-tight mb-2">
                    {email.snippet}
                  </p>

                  {/* Warning Pill & Quick Scan Action */}
                  <div className="flex items-center justify-between gap-1.5 flex-wrap">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase tracking-wider ${pillStyle}`}
                      >
                        {rep?.overallRiskLevel === 'critical' && '🔴 Phishing'}
                        {rep?.overallRiskLevel === 'warning' && '🟠 Suspicious'}
                        {rep?.overallRiskLevel === 'caution' && '🟡 External'}
                        {rep?.overallRiskLevel === 'safe' && '🟢 Safe'}
                      </span>

                      {email.isExternal && (
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                          Ext.
                        </span>
                      )}

                      {email.attachments.length > 0 && (
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 flex items-center gap-1 border border-slate-700">
                          <Paperclip className="w-2.5 h-2.5" />
                          {email.attachments.length}
                        </span>
                      )}
                    </div>

                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedEmailId(email.id);
                        handleTriggerScan(false, email);
                      }}
                      className="text-[10px] font-semibold px-2 py-0.5 rounded bg-sky-950/80 hover:bg-sky-900 text-sky-300 border border-sky-600/40 transition-colors cursor-pointer flex items-center gap-1"
                      title="Run Phishing Guard scan on this email"
                    >
                      <Shield className="w-2.5 h-2.5" />
                      <span>Scan</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Email Detail View with Injected Extension Overlays */}
        <div className="flex-1 bg-slate-900/10 flex flex-col overflow-y-auto">
          <div className="p-4 md:p-6 max-w-4xl mx-auto w-full space-y-4">
            {/* Email Subject Header & Scan Toolbar */}
            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-2 border-b border-slate-800/80">
              <div>
                <h1 className="text-lg md:text-xl font-bold text-white tracking-tight">
                  {currentEmail.subject}
                </h1>
                <div className="flex items-center gap-2 mt-2 flex-wrap">
                  {currentEmail.tags.map((tag) => (
                    <span
                      key={tag}
                      className="text-[11px] font-medium px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700"
                    >
                      {tag}
                    </span>
                  ))}
                  {currentEmail.isExternal ? (
                    <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-amber-950/60 text-amber-300 border border-amber-500/40">
                      ⚠️ External Organization ({currentEmail.sender.domain})
                    </span>
                  ) : (
                    <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-emerald-950/60 text-emerald-300 border border-emerald-500/40">
                      🏢 Internal Acme Corp
                    </span>
                  )}
                </div>
              </div>

              {/* Dedicated Scan Buttons in Detail View Header */}
              <div className="flex items-center gap-2 flex-shrink-0">
                <button
                  id="scan-email-action-btn"
                  onClick={() => handleTriggerScan(false)}
                  disabled={isDeepScanning}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs shadow-md shadow-sky-600/30 transition-all cursor-pointer disabled:opacity-50"
                  title="Click to scan this email with Gmail Phishing Guard"
                >
                  <Shield className="w-4 h-4" />
                  <span>{isDeepScanning ? 'Scanning...' : '🛡️ Scan Email'}</span>
                </button>

                <button
                  id="ai-deep-scan-header-btn"
                  onClick={() => handleTriggerScan(true)}
                  disabled={isDeepScanning}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-indigo-600/30 hover:bg-indigo-600/50 border border-indigo-500/50 text-indigo-200 font-semibold text-xs transition-colors cursor-pointer disabled:opacity-50"
                  title="Run deep AI analysis on social engineering indicators"
                >
                  <Sparkles className="w-3.5 h-3.5 text-indigo-300" />
                  <span className="hidden sm:inline">AI Deep Scan</span>
                </button>

                <button
                  id="view-report-modal-btn"
                  onClick={() => setShowReportModal(true)}
                  className="px-2.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 font-semibold text-xs transition-colors cursor-pointer"
                  title="Open full Security Scan Report"
                >
                  Report
                </button>
              </div>
            </div>

            {/* Sender and Authentication Meta Card */}
            <div className="p-3.5 bg-slate-900 rounded-xl border border-slate-800 flex items-center justify-between flex-wrap gap-3">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-sm text-sky-400">
                  {currentEmail.sender.name.charAt(0)}
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold text-sm text-slate-100">
                      {currentEmail.sender.name}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">
                      &lt;{currentEmail.sender.email}&gt;
                    </span>
                  </div>
                  <div className="text-xs text-slate-400 mt-0.5 flex items-center gap-3 flex-wrap">
                    <span>to: {currentEmail.recipient}</span>
                    <span>• {currentEmail.date}</span>
                  </div>
                </div>
              </div>

              {/* Authentication Badges (SPF / DKIM / DMARC) */}
              <div className="flex items-center gap-1.5 text-[11px]">
                <span
                  title="Sender Policy Framework verification status"
                  className={`px-2 py-0.5 rounded font-mono font-semibold border ${
                    currentEmail.headers.spf === 'pass'
                      ? 'bg-emerald-950/60 text-emerald-300 border-emerald-500/30'
                      : 'bg-red-950/60 text-red-300 border-red-500/30'
                  }`}
                >
                  SPF: {currentEmail.headers.spf.toUpperCase()}
                </span>
                <span
                  title="DomainKeys Identified Mail verification status"
                  className={`px-2 py-0.5 rounded font-mono font-semibold border ${
                    currentEmail.headers.dkim === 'pass'
                      ? 'bg-emerald-950/60 text-emerald-300 border-emerald-500/30'
                      : 'bg-red-950/60 text-red-300 border-red-500/30'
                  }`}
                >
                  DKIM: {currentEmail.headers.dkim.toUpperCase()}
                </span>
                <span
                  title="Domain-based Message Authentication status"
                  className={`px-2 py-0.5 rounded font-mono font-semibold border ${
                    currentEmail.headers.dmarc === 'pass'
                      ? 'bg-emerald-950/60 text-emerald-300 border-emerald-500/30'
                      : 'bg-red-950/60 text-red-300 border-red-500/30'
                  }`}
                >
                  DMARC: {currentEmail.headers.dmarc.toUpperCase()}
                </span>
              </div>
            </div>

            {/* EXTENSION INJECTED SECURITY BANNER */}
            <SecurityBanner
              report={currentReport}
              onDeepScan={handleDeepScan}
              isDeepScanning={isDeepScanning}
              onReportPhishing={handleReportPhishing}
              reported={Boolean(reportedEmails[currentEmail.id])}
            />

            {/* Email Body with interactive link inspector */}
            <div className="p-6 bg-slate-900/80 rounded-2xl border border-slate-800 shadow-inner">
              <div
                className="prose prose-invert max-w-none text-slate-200 text-sm leading-relaxed"
                dangerouslySetHtml={{ __html: processedBodyHtml }}
                onClick={handleBodyClick}
              />
            </div>

            {/* Injected Attachments Section with Color-Coded Threat Indicators */}
            {currentReport.attachments.length > 0 && (
              <div className="p-4 bg-slate-900 rounded-xl border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 uppercase tracking-wider">
                    <Paperclip className="w-4 h-4 text-slate-400" />
                    <span>Attachments ({currentReport.attachments.length}) - Scanned by Guard:</span>
                  </div>
                  <span className="text-[11px] text-slate-400">Sandbox extension rule evaluation</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {currentReport.attachments.map((att) => {
                    const isCritical = att.riskLevel === 'critical';
                    const isWarning = att.riskLevel === 'warning';
                    const isCaution = att.riskLevel === 'caution';
                    const isSafe = att.riskLevel === 'safe';

                    const borderClass = isCritical
                      ? 'border-red-500/70 bg-red-950/20 hover:bg-red-950/30'
                      : isWarning
                      ? 'border-amber-500/70 bg-amber-950/20 hover:bg-amber-950/30'
                      : isCaution
                      ? 'border-yellow-500/50 bg-yellow-950/20'
                      : 'border-slate-800 bg-slate-950/50 hover:bg-slate-800/40';

                    return (
                      <div
                        key={att.id}
                        className={`p-3 rounded-xl border transition-all ${borderClass}`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center gap-2.5">
                            <div className="p-2 rounded-lg bg-slate-800 border border-slate-700">
                              {getAttachmentIcon(att.filename)}
                            </div>
                            <div className="overflow-hidden">
                              <div className="font-mono text-xs font-medium text-slate-200 truncate max-w-[200px]" title={att.filename}>
                                {att.filename}
                              </div>
                              <span className="text-[10px] text-slate-400">{att.size}</span>
                            </div>
                          </div>

                          {/* Risk Badge Tag */}
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                              isCritical
                                ? 'bg-red-600 text-white'
                                : isWarning
                                ? 'bg-amber-600 text-white'
                                : isCaution
                                ? 'bg-yellow-600 text-white'
                                : 'bg-emerald-600 text-white'
                            }`}
                          >
                            {isCritical && '🔴 DANGEROUS'}
                            {isWarning && '🟠 SUSPICIOUS'}
                            {isCaution && '🟡 CAUTION'}
                            {isSafe && '🟢 SAFE'}
                          </span>
                        </div>

                        {/* Anomaly note if detected */}
                        {att.issues && att.issues.length > 0 && (
                          <div className="mt-2 text-[11px] p-2 rounded bg-slate-950/70 border border-white/5 space-y-1">
                            {att.issues.map((iss, i) => (
                              <div key={i} className="flex items-start gap-1.5 text-red-300">
                                <AlertTriangle className="w-3 h-3 text-red-400 flex-shrink-0 mt-0.5" />
                                <span>{iss}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Floating Persistent Scan Button (matches Chrome Extension floating badge) */}
      <div className="fixed bottom-5 right-5 z-40">
        <button
          id="floating-scan-guard-btn"
          onClick={() => handleTriggerScan(false)}
          disabled={isDeepScanning}
          className="flex items-center gap-2.5 px-4 py-2.5 rounded-full bg-slate-900 hover:bg-slate-800 text-white border-2 border-sky-400 shadow-2xl hover:scale-105 transition-all cursor-pointer group disabled:opacity-50"
          title="Click to scan currently viewed email with Phishing Guard"
        >
          <span className="w-2.5 h-2.5 rounded-full bg-sky-400 animate-pulse" />
          <Shield className="w-4 h-4 text-sky-400 group-hover:rotate-12 transition-transform" />
          <span className="font-bold text-xs tracking-wide">
            {isDeepScanning ? 'Scanning...' : 'Scan Email with Guard'}
          </span>
        </button>
      </div>

      {/* Toast Notification */}
      {scanNotification && (
        <div className="fixed top-16 left-1/2 -translate-x-1/2 z-50 bg-slate-900 border border-sky-500/50 text-sky-200 text-xs font-semibold px-4 py-2 rounded-full shadow-xl flex items-center gap-2 animate-in fade-in slide-in-from-top-2 duration-200">
          <Shield className="w-4 h-4 text-sky-400" />
          <span>{scanNotification}</span>
        </div>
      )}

      {/* Security Scan Report Modal */}
      {showReportModal && (
        <div
          className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto"
          onClick={() => setShowReportModal(false)}
        >
          <div
            className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-xl max-h-[85vh] overflow-y-auto shadow-2xl p-5 space-y-4"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-sky-400" />
                <h2 className="text-base font-bold text-white tracking-tight">
                  Security Scan Report
                </h2>
              </div>
              <button
                onClick={() => setShowReportModal(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Verdict Card */}
            <div
              className={`p-4 rounded-xl border flex items-center justify-between ${
                currentReport.overallRiskLevel === 'critical'
                  ? 'bg-red-950/30 border-red-500/50 text-red-200'
                  : currentReport.overallRiskLevel === 'warning'
                  ? 'bg-amber-950/30 border-amber-500/50 text-amber-200'
                  : currentReport.overallRiskLevel === 'caution'
                  ? 'bg-yellow-950/30 border-yellow-500/50 text-yellow-200'
                  : 'bg-emerald-950/30 border-emerald-500/50 text-emerald-200'
              }`}
            >
              <div>
                <div className="text-[10px] uppercase font-bold tracking-widest opacity-80">
                  Phishing Guard Assessment
                </div>
                <div className="text-lg font-black tracking-tight mt-0.5">
                  {currentReport.overallRiskLevel === 'critical' && '🔴 CRITICAL PHISHING THREAT'}
                  {currentReport.overallRiskLevel === 'warning' && '🟠 SUSPICIOUS EMAIL'}
                  {currentReport.overallRiskLevel === 'caution' && '🟡 EXTERNAL SENDER CAUTION'}
                  {currentReport.overallRiskLevel === 'safe' && '🟢 VERIFIED SAFE'}
                </div>
              </div>
              <div className="text-right">
                <div className="text-[10px] opacity-80 uppercase font-semibold">Risk Score</div>
                <div className="text-2xl font-black font-mono">
                  {currentReport.overallScore}
                  <span className="text-xs font-normal opacity-70">/100</span>
                </div>
              </div>
            </div>

            {/* Sender & Auth Summary */}
            <div className="p-3 bg-slate-950/70 rounded-xl border border-slate-800 text-xs space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Sender:</span>
                <span className="font-semibold text-slate-200">{currentEmail.sender.name} &lt;{currentEmail.sender.email}&gt;</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Origin:</span>
                <span className={currentEmail.isExternal ? 'text-amber-400 font-semibold' : 'text-emerald-400 font-semibold'}>
                  {currentEmail.isExternal ? '⚠️ External Source' : '🏢 Internal Corporate'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">SPF / DKIM / DMARC:</span>
                <span className="font-mono text-[11px] text-slate-300">
                  {currentEmail.headers.spf.toUpperCase()} / {currentEmail.headers.dkim.toUpperCase()} / {currentEmail.headers.dmarc.toUpperCase()}
                </span>
              </div>
            </div>

            {/* Threat Indicators */}
            {currentReport.reasons.length > 0 ? (
              <div className="space-y-2">
                <div className="text-xs font-bold text-red-300 uppercase tracking-wider">
                  ⚠️ Flagged Threat Anomalies ({currentReport.reasons.length})
                </div>
                <ul className="space-y-1.5 bg-slate-950/60 p-3 rounded-xl border border-slate-800 text-xs text-slate-300">
                  {currentReport.reasons.map((reason, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400 flex-shrink-0 mt-0.5" />
                      <span>{reason}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                <span>No deceptive link targets, typosquatting domains, or dangerous attachments detected.</span>
              </div>
            )}

            {/* Analyzed Links Quick Review */}
            {currentReport.links.length > 0 && (
              <div className="space-y-1.5">
                <div className="text-xs font-bold text-slate-300">
                  Links Evaluated ({currentReport.links.length}):
                </div>
                <div className="max-h-32 overflow-y-auto space-y-1">
                  {currentReport.links.map((link) => (
                    <div
                      key={link.id}
                      className="p-2 rounded-lg bg-slate-950/60 border border-slate-800 text-[11px] flex items-center justify-between gap-2"
                    >
                      <div className="truncate">
                        <span className="text-slate-400">Anchor: </span>
                        <span className="font-mono text-slate-200">{link.anchorText}</span>
                        <span className="text-slate-400 ml-2">Target: </span>
                        <span className="font-mono text-sky-400">{link.targetDomain}</span>
                      </div>
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded uppercase ${
                        link.riskLevel === 'critical' ? 'bg-red-600 text-white' :
                        link.riskLevel === 'warning' ? 'bg-amber-600 text-white' :
                        link.riskLevel === 'caution' ? 'bg-yellow-600 text-white' :
                        'bg-emerald-600 text-white'
                      }`}>
                        {link.riskLevel}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Modal Actions */}
            <div className="flex items-center justify-between pt-3 border-t border-slate-800">
              <button
                onClick={() => handleTriggerScan(true)}
                disabled={isDeepScanning}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600/30 hover:bg-indigo-600/50 border border-indigo-500/50 text-indigo-200 text-xs font-semibold transition-colors cursor-pointer"
              >
                <Sparkles className="w-3.5 h-3.5 text-indigo-300" />
                <span>Rerun with AI Deep Scan</span>
              </button>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    handleReportPhishing();
                    setShowReportModal(false);
                    setScanNotification('🚩 Reported to security team & quarantined');
                    setTimeout(() => setScanNotification(null), 4000);
                  }}
                  className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-bold transition-colors cursor-pointer"
                >
                  Quarantine & Report
                </button>
                <button
                  onClick={() => setShowReportModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors cursor-pointer"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Interactive Link Inspector Modal */}
      <LinkInspectorModal
        link={inspectedLink}
        onClose={() => setInspectedLink(null)}
      />
    </div>
  );
};

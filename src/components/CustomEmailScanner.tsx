import React, { useState } from 'react';
import {
  Sparkles,
  ArrowLeft,
  ShieldAlert,
  Send,
  Plus,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  FileCode,
  Link as LinkIcon,
} from 'lucide-react';
import { EmailMessage, EmailScanReport } from '../types';
import { scanEmailHeuristic, requestDeepAiScan } from '../utils/phishingScanner';
import { SecurityBanner } from './SecurityBanner';

interface CustomEmailScannerProps {
  onBack: () => void;
  onAddToInbox: (email: EmailMessage) => void;
}

export const CustomEmailScanner: React.FC<CustomEmailScannerProps> = ({
  onBack,
  onAddToInbox,
}) => {
  const [senderName, setSenderName] = useState('Netflix Account Billing');
  const [senderEmail, setSenderEmail] = useState('notifications@netfl1x-verify-payment.xyz');
  const [isExternal, setIsExternal] = useState(true);
  const [subject, setSubject] = useState('Payment declined: Update credit card within 12 hours');
  const [bodyText, setBodyText] = useState(
    `Dear Member,\n\nWe were unable to process your monthly subscription payment. Your membership is scheduled for immediate suspension.\n\nTo restore continuous streaming, click the secure verification link below:\n👉 Update Billing Details: https://netflix.com/youraccount/billing\n\nDirect secure URL: http://netfl1x-verify-payment.xyz/login.php?user=auth\n\nNetflix Customer Support`
  );
  const [attachmentList, setAttachmentList] = useState<string[]>([
    'BillingReceipt_Statement.pdf.exe',
  ]);
  const [newAttName, setNewAttName] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<EmailScanReport | null>(null);
  const [reported, setReported] = useState(false);

  const handleAddAttachment = () => {
    if (newAttName.trim()) {
      setAttachmentList([...attachmentList, newAttName.trim()]);
      setNewAttName('');
    }
  };

  const handleRemoveAttachment = (idx: number) => {
    setAttachmentList(attachmentList.filter((_, i) => i !== idx));
  };

  const buildCurrentEmailObject = (): EmailMessage => {
    const senderDomain = senderEmail.split('@')[1] || 'unknown.com';

    // Convert plain text into basic HTML with links
    const bodyHtml = `
      <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #222;">
        ${bodyText
          .split('\n')
          .map((line) => {
            if (line.includes('http://') || line.includes('https://')) {
              // Wrap URLs into <a> tags
              return line.replace(
                /(https?:\/\/[^\s]+)/g,
                '<a href="$1" target="_blank" style="color: #0066cc;">$1</a>'
              );
            }
            return `<p>${line || '&nbsp;'}</p>`;
          })
          .join('')}
      </div>
    `;

    return {
      id: `custom-${Date.now()}`,
      sender: {
        name: senderName,
        email: senderEmail,
        domain: senderDomain,
        isExternal,
      },
      recipient: 'employee@acmecorp.com',
      date: 'Just now',
      subject,
      snippet: bodyText.slice(0, 120) + '...',
      bodyText,
      bodyHtml,
      isExternal,
      headers: {
        spf: 'fail',
        dkim: 'fail',
        dmarc: 'fail',
      },
      tags: ['Custom', isExternal ? 'External' : 'Internal'],
      attachments: attachmentList.map((filename, i) => ({
        id: `att-custom-${i}`,
        filename,
        size: '450 KB',
        type: 'application/octet-stream',
      })),
    };
  };

  const handleRunScan = async (useAi: boolean = false) => {
    setIsScanning(true);
    const emailObj = buildCurrentEmailObject();
    try {
      if (useAi) {
        const rep = await requestDeepAiScan(emailObj);
        setScanResult(rep);
      } else {
        const rep = scanEmailHeuristic(emailObj);
        setScanResult(rep);
      }
    } finally {
      setIsScanning(false);
    }
  };

  const handleApplyPreset = (preset: 'paypal' | 'ceo' | 'legit') => {
    if (preset === 'paypal') {
      setSenderName('PayPal Resolution Center');
      setSenderEmail('service@paypaI-resolution-case.com');
      setIsExternal(true);
      setSubject('Account Limited: Confirm Identity to lift transaction restrictions');
      setBodyText(
        `Dear PayPal Customer,\n\nUnusual transaction activity was observed from your account. An unauthorized dispute of $420.00 was raised.\n\nVerify your account ownership at:\n👉 http://paypaI-resolution-case.com/verify?id=94801\n\nOr download the resolution dispute case manifest: PayPal_Case_94802.pdf.scr\n\nPayPal Security Center`
      );
      setAttachmentList(['PayPal_Case_94802.pdf.scr']);
    } else if (preset === 'ceo') {
      setSenderName('Chief Financial Officer');
      setSenderEmail('cfo.urgent.internal@outlook.com');
      setIsExternal(true);
      setSubject('Immediate Wire Transfer Authorization Needed Before Bank Cutoff');
      setBodyText(
        `Hi Team,\n\nI am currently boarding a cross-country flight and cannot receive cellular calls.\n\nWe must transmit a deposit of $68,000 for our pending equipment lease by 1:00 PM EST.\n\nKindly retrieve wire routing codes from: http://195.123.44.20/wire-instructions.zip\n\nConfirm once sent.\n\nCFO Office`
      );
      setAttachmentList(['wire-instructions.zip']);
    } else {
      setSenderName('Atlassian Jira Cloud');
      setSenderEmail('notifications@jira.atlassian.net');
      setIsExternal(true);
      setSubject('Daily Sprint Summary: 8 tickets resolved in Sprint 42');
      setBodyText(
        `Hello,\n\nHere is your daily Jira recap for the development team.\n\nView active sprint board: https://jira.atlassian.net/jira/software/projects/PROJ/boards/42\n\nAttached is the sprint burn-down chart export.\n\nAtlassian Team`
      );
      setAttachmentList(['Sprint_Burndown_Export.pdf']);
    }
  };

  return (
    <div className="h-full flex flex-col bg-slate-950 text-slate-100 overflow-y-auto">
      {/* Top Bar */}
      <div className="h-14 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between px-4 flex-shrink-0">
        <button
          onClick={onBack}
          className="flex items-center gap-2 text-xs text-slate-300 hover:text-white px-2.5 py-1.5 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Gmail Inbox</span>
        </button>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">Quick Test Templates:</span>
          <button
            onClick={() => handleApplyPreset('paypal')}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-red-300 border border-red-500/30 transition-colors cursor-pointer"
          >
            PayPal Phish
          </button>
          <button
            onClick={() => handleApplyPreset('ceo')}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-amber-300 border border-amber-500/30 transition-colors cursor-pointer"
          >
            CEO Wire Lure
          </button>
          <button
            onClick={() => handleApplyPreset('legit')}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-emerald-300 border border-emerald-500/30 transition-colors cursor-pointer"
          >
            Safe Partner
          </button>
        </div>
      </div>

      <div className="flex-1 p-4 md:p-8 max-w-5xl mx-auto w-full space-y-6">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-sky-400" />
            <span>Custom Email Phishing Scanner Testbench</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Simulate or paste any external email to observe how the Chrome extension scans links, attachments, and headers.
          </p>
        </div>

        {/* Input Form Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-3 bg-slate-900 p-4 rounded-2xl border border-slate-800">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Sender Display Name</label>
              <input
                type="text"
                value={senderName}
                onChange={(e) => setSenderName(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-100 focus:outline-none focus:border-sky-500"
                placeholder="e.g. Google Support"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Sender Email Address</label>
              <input
                type="email"
                value={senderEmail}
                onChange={(e) => setSenderEmail(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-500"
                placeholder="e.g. alert@googIe-support.xyz"
              />
            </div>

            <div className="flex items-center gap-2 pt-1">
              <input
                type="checkbox"
                id="isExternalCheck"
                checked={isExternal}
                onChange={(e) => setIsExternal(e.target.checked)}
                className="rounded border-slate-700 text-sky-500 focus:ring-sky-500 h-4 w-4 cursor-pointer"
              />
              <label htmlFor="isExternalCheck" className="text-xs text-slate-300 cursor-pointer">
                Originates from an External Source (outside internal company domain)
              </label>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">Subject Line</label>
              <input
                type="text"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-100 focus:outline-none focus:border-sky-500"
                placeholder="e.g. Urgent: Verify account credentials"
              />
            </div>
          </div>

          <div className="space-y-3 bg-slate-900 p-4 rounded-2xl border border-slate-800 flex flex-col justify-between">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Attachments to Test (Double extensions, macros, executables)
              </label>
              <div className="flex gap-2 mb-2">
                <input
                  type="text"
                  value={newAttName}
                  onChange={(e) => setNewAttName(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleAddAttachment()}
                  placeholder="e.g. Invoice.pdf.exe or Manifest.docm"
                  className="flex-1 px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-xl text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-500"
                />
                <button
                  onClick={handleAddAttachment}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-xl border border-slate-700 transition-colors cursor-pointer"
                >
                  <Plus className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-1 max-h-36 overflow-y-auto">
                {attachmentList.map((att, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300"
                  >
                    <span>{att}</span>
                    <button
                      onClick={() => handleRemoveAttachment(i)}
                      className="text-slate-500 hover:text-red-400 transition-colors cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-2 flex items-center gap-2">
              <button
                onClick={() => handleRunScan(false)}
                disabled={isScanning}
                className="flex-1 py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold transition-colors disabled:opacity-50 cursor-pointer"
              >
                {isScanning ? 'Evaluating Rules...' : 'Run Extension Heuristic Scan'}
              </button>

              <button
                onClick={() => handleRunScan(true)}
                disabled={isScanning}
                className="flex-1 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50 cursor-pointer"
              >
                {isScanning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5 text-indigo-200" />}
                <span>Scan with Gemini AI</span>
              </button>
            </div>
          </div>
        </div>

        {/* Email Body Text Input */}
        <div className="bg-slate-900 p-4 rounded-2xl border border-slate-800 space-y-2">
          <label className="block text-xs font-semibold text-slate-300">
            Email Body Content (Includes links to test lookalike domains, IP URLs, shorteners, mismatches)
          </label>
          <textarea
            rows={6}
            value={bodyText}
            onChange={(e) => setBodyText(e.target.value)}
            className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-500"
          />
        </div>

        {/* Scan Result Injected Preview */}
        {scanResult && (
          <div className="space-y-4 pt-4 border-t border-slate-800">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>Extension Scan Output & Injected Banner Preview</span>
              </h3>
              <button
                onClick={() => onAddToInbox(buildCurrentEmailObject())}
                className="px-3 py-1.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <span>Import to Gmail Simulator</span>
                <Send className="w-3 h-3" />
              </button>
            </div>

            {/* Injected Banner Preview */}
            <SecurityBanner
              report={scanResult}
              onDeepScan={() => handleRunScan(true)}
              isDeepScanning={isScanning}
              onReportPhishing={() => setReported(true)}
              reported={reported}
            />

            {/* Link & Attachment Risk Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Links summary */}
              <div className="bg-slate-900 p-4 rounded-2xl border border-slate-800 space-y-2">
                <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                  <LinkIcon className="w-3.5 h-3.5 text-sky-400" />
                  <span>Links Identified ({scanResult.links.length})</span>
                </div>
                {scanResult.links.length === 0 ? (
                  <p className="text-xs text-slate-500">No external links found in email body.</p>
                ) : (
                  <div className="space-y-2">
                    {scanResult.links.map((l, idx) => (
                      <div
                        key={idx}
                        className={`p-2.5 rounded-xl border text-xs ${
                          l.riskLevel === 'critical'
                            ? 'bg-red-950/20 border-red-500/40 text-red-200'
                            : l.riskLevel === 'warning'
                            ? 'bg-amber-950/20 border-amber-500/40 text-amber-200'
                            : 'bg-slate-950 border-slate-800 text-slate-300'
                        }`}
                      >
                        <div className="font-mono break-all font-semibold">{l.url}</div>
                        {l.issues && l.issues.length > 0 && (
                          <ul className="mt-1 space-y-0.5 text-[11px] text-red-300 list-disc list-inside">
                            {l.issues.map((iss, i) => (
                              <li key={i}>{iss}</li>
                            ))}
                          </ul>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Attachments summary */}
              <div className="bg-slate-900 p-4 rounded-2xl border border-slate-800 space-y-2">
                <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-sky-400" />
                  <span>Attachments Scanned ({scanResult.attachments.length})</span>
                </div>
                {scanResult.attachments.length === 0 ? (
                  <p className="text-xs text-slate-500">No attachments attached.</p>
                ) : (
                  <div className="space-y-2">
                    {scanResult.attachments.map((att, idx) => (
                      <div
                        key={idx}
                        className={`p-2.5 rounded-xl border text-xs ${
                          att.riskLevel === 'critical'
                            ? 'bg-red-950/20 border-red-500/40 text-red-200'
                            : att.riskLevel === 'warning'
                            ? 'bg-amber-950/20 border-amber-500/40 text-amber-200'
                            : 'bg-slate-950 border-slate-800 text-slate-300'
                        }`}
                      >
                        <div className="font-mono font-semibold">{att.filename}</div>
                        {att.issues && att.issues.length > 0 && (
                          <ul className="mt-1 space-y-0.5 text-[11px] text-red-300 list-disc list-inside">
                            {att.issues.map((iss, i) => (
                              <li key={i}>{iss}</li>
                            ))}
                          </ul>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

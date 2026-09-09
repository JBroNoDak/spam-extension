import React from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Info,
  ShieldCheck,
  Copy,
  ExternalLink,
  X,
  Lock,
  Globe,
  Check,
} from 'lucide-react';
import { EmailLink, RiskLevel } from '../types';

interface LinkInspectorModalProps {
  link: EmailLink | null;
  onClose: () => void;
}

export const LinkInspectorModal: React.FC<LinkInspectorModalProps> = ({ link, onClose }) => {
  const [copied, setCopied] = React.useState(false);

  if (!link) return null;

  const riskLevel: RiskLevel = link.riskLevel || 'safe';

  const riskBadgeConfig: Record<
    RiskLevel,
    { label: string; bg: string; text: string; border: string; icon: React.ReactNode }
  > = {
    critical: {
      label: 'CRITICAL PHISHING THREAT',
      bg: 'bg-red-500/20',
      text: 'text-red-300',
      border: 'border-red-500/40',
      icon: <ShieldAlert className="w-5 h-5 text-red-400" />,
    },
    warning: {
      label: 'SUSPICIOUS LINK DESTINATION',
      bg: 'bg-amber-500/20',
      text: 'text-amber-300',
      border: 'border-amber-500/40',
      icon: <AlertTriangle className="w-5 h-5 text-amber-400" />,
    },
    caution: {
      label: 'UNVERIFIED EXTERNAL LINK',
      bg: 'bg-yellow-500/20',
      text: 'text-yellow-300',
      border: 'border-yellow-500/40',
      icon: <Info className="w-5 h-5 text-yellow-400" />,
    },
    safe: {
      label: 'VERIFIED LINK REPUTATION',
      bg: 'bg-emerald-500/20',
      text: 'text-emerald-300',
      border: 'border-emerald-500/40',
      icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />,
    },
  };

  const badge = riskBadgeConfig[riskLevel];

  let parsedHost = '';
  let parsedProtocol = '';
  try {
    const u = new URL(link.url);
    parsedHost = u.hostname;
    parsedProtocol = u.protocol;
  } catch {
    parsedHost = link.url;
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(link.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      id="link-inspector-backdrop"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs animate-in fade-in duration-150"
      onClick={onClose}
    >
      <div
        id="link-inspector-dialog"
        className="w-full max-w-lg bg-slate-900 border border-slate-700 rounded-2xl p-6 shadow-2xl space-y-4 text-slate-100"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            {badge.icon}
            <div>
              <div className="flex items-center gap-2">
                <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full border ${badge.bg} ${badge.text} ${badge.border}`}>
                  {badge.label}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">Gmail Phishing Guard Link Inspection</p>
            </div>
          </div>
          <button
            id="close-link-inspector-btn"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Display Text vs Actual URL Comparison */}
        <div className="space-y-3 bg-slate-950/80 p-3.5 rounded-xl border border-slate-800 text-xs">
          <div>
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
              Anchor Text Visible to User:
            </span>
            <div className="p-2 bg-slate-900 rounded border border-slate-800 font-mono text-slate-200 break-all">
              {link.text || '(Image or icon link)'}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                Actual Target URL (Destination):
              </span>
              <span className="text-[10px] text-red-400 font-medium">True Link Href</span>
            </div>
            <div className="p-2 bg-red-950/20 rounded border border-red-900/50 font-mono text-red-300 break-all flex items-center justify-between gap-2">
              <span>{link.url}</span>
              <button
                id="copy-target-url-btn"
                onClick={handleCopy}
                title="Copy Destination URL"
                className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors flex-shrink-0 cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>

        {/* Domain Breakdown */}
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="bg-slate-800/60 p-2.5 rounded-lg border border-slate-700/50">
            <span className="text-[10px] text-slate-400 block uppercase">Destination Host</span>
            <div className="flex items-center gap-1.5 font-mono font-medium text-slate-200 mt-1 truncate">
              <Globe className="w-3.5 h-3.5 text-sky-400 flex-shrink-0" />
              <span className="truncate">{parsedHost}</span>
            </div>
          </div>

          <div className="bg-slate-800/60 p-2.5 rounded-lg border border-slate-700/50">
            <span className="text-[10px] text-slate-400 block uppercase">Protocol Encryption</span>
            <div className="flex items-center gap-1.5 font-mono font-medium text-slate-200 mt-1">
              <Lock className={`w-3.5 h-3.5 flex-shrink-0 ${parsedProtocol === 'https:' ? 'text-emerald-400' : 'text-red-400'}`} />
              <span className={parsedProtocol === 'https:' ? 'text-emerald-300' : 'text-red-300'}>
                {parsedProtocol.toUpperCase() || 'UNKNOWN'}
              </span>
            </div>
          </div>
        </div>

        {/* Issues List */}
        {link.issues && link.issues.length > 0 ? (
          <div className="space-y-1.5">
            <span className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider block">
              Flagged Risk Anomaly Details:
            </span>
            <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800 space-y-1.5">
              {link.issues.map((issue, idx) => (
                <div key={idx} className="flex items-start gap-2 text-xs text-red-300">
                  <span className="text-red-400 mt-0.5">•</span>
                  <span>{issue}</span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="p-3 bg-emerald-950/30 border border-emerald-500/30 rounded-xl text-xs text-emerald-300 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>No immediate domain spoofing or deceptive redirection found.</span>
          </div>
        )}

        {/* Advisory Warning */}
        {riskLevel === 'critical' && (
          <div className="p-3 bg-red-950/40 border border-red-500/40 rounded-xl text-xs text-red-200 flex items-start gap-2">
            <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <strong>Navigation Blocked for Your Protection:</strong> Gmail Phishing Guard recommends avoiding this link. Phishing attackers routinely use domain homoglyphs to harvest corporate credentials.
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="pt-2 flex items-center justify-end gap-2.5">
          <button
            id="modal-dismiss-btn"
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors cursor-pointer"
          >
            Close & Stay Safe
          </button>
        </div>
      </div>
    </div>
  );
};

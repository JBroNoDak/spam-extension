import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Sparkles,
  ExternalLink,
  CheckCircle2,
  RefreshCw,
  Flag,
} from 'lucide-react';
import { EmailScanReport, RiskLevel } from '../types';

interface SecurityBannerProps {
  report: EmailScanReport;
  onDeepScan: () => void;
  isDeepScanning: boolean;
  onReportPhishing: () => void;
  reported: boolean;
}

export const SecurityBanner: React.FC<SecurityBannerProps> = ({
  report,
  onDeepScan,
  isDeepScanning,
  onReportPhishing,
  reported,
}) => {
  const { overallRiskLevel, overallScore, isExternal, heuristicSignals, aiAnalysis } = report;

  const colorConfig: Record<
    RiskLevel,
    {
      bg: string;
      border: string;
      accent: string;
      badgeBg: string;
      badgeText: string;
      text: string;
      icon: React.ReactNode;
      label: string;
    }
  > = {
    critical: {
      bg: 'bg-red-950/40',
      border: 'border-red-500/80',
      accent: 'text-red-400',
      badgeBg: 'bg-red-500/20',
      badgeText: 'text-red-300 border-red-500/40',
      text: 'text-red-200',
      icon: <ShieldAlert className="w-5 h-5 text-red-400 flex-shrink-0" />,
      label: 'CRITICAL PHISHING ATTEMPT DETECTED',
    },
    warning: {
      bg: 'bg-amber-950/40',
      border: 'border-amber-500/80',
      accent: 'text-amber-400',
      badgeBg: 'bg-amber-500/20',
      badgeText: 'text-amber-300 border-amber-500/40',
      text: 'text-amber-200',
      icon: <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0" />,
      label: 'SUSPICIOUS EXTERNAL EMAIL - PROCEED WITH CAUTION',
    },
    caution: {
      bg: 'bg-yellow-950/30',
      border: 'border-yellow-500/60',
      accent: 'text-yellow-400',
      badgeBg: 'bg-yellow-500/20',
      badgeText: 'text-yellow-300 border-yellow-500/40',
      text: 'text-yellow-200',
      icon: <Info className="w-5 h-5 text-yellow-400 flex-shrink-0" />,
      label: 'EXTERNAL SOURCE - UNVERIFIED DOMAIN',
    },
    safe: {
      bg: 'bg-emerald-950/30',
      border: 'border-emerald-500/60',
      accent: 'text-emerald-400',
      badgeBg: 'bg-emerald-500/20',
      badgeText: 'text-emerald-300 border-emerald-500/40',
      text: 'text-emerald-200',
      icon: <ShieldCheck className="w-5 h-5 text-emerald-400 flex-shrink-0" />,
      label: 'VERIFIED SOURCE - NO KNOWN THREATS FOUND',
    },
  };

  const cfg = colorConfig[overallRiskLevel];

  return (
    <div
      id="gpg-injected-banner"
      className={`rounded-xl border p-4 mb-5 shadow-lg backdrop-blur-sm transition-all ${cfg.bg} ${cfg.border}`}
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-white/10">
        <div className="flex items-center gap-2.5">
          {cfg.icon}
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`text-xs font-bold tracking-wider uppercase border px-2 py-0.5 rounded-full ${cfg.badgeBg} ${cfg.badgeText}`}>
                {cfg.label}
              </span>
              {isExternal && (
                <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                  External Origin
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Score & AI Scan Button */}
        <div className="flex items-center gap-2 self-end sm:self-auto">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900/80 border border-slate-700 text-xs">
            <span className="text-slate-400">Risk Score:</span>
            <span className={`font-mono font-bold ${cfg.accent}`}>{overallScore}/100</span>
          </div>

          <button
            id="deep-ai-scan-btn"
            onClick={onDeepScan}
            disabled={isDeepScanning}
            className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium transition-colors disabled:opacity-50 cursor-pointer"
          >
            {isDeepScanning ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Sparkles className="w-3.5 h-3.5 text-indigo-200" />
            )}
            <span>{isDeepScanning ? 'Analyzing...' : 'AI Deep Scan'}</span>
          </button>
        </div>
      </div>

      {/* Description & Detected Signals */}
      <div className="mt-3 text-xs space-y-2">
        <p className="text-slate-300 leading-relaxed">
          {overallRiskLevel === 'critical' &&
            'Warning: This email exhibits characteristics of a targeted attack or credential harvesting attempt. External sender identity is deceptive, and links/attachments pose high risk.'}
          {overallRiskLevel === 'warning' &&
            'Caution: Potential security risks detected. Links point to obscured destinations or attachments contain executable/macro code capabilities.'}
          {overallRiskLevel === 'caution' &&
            'Notice: This email originated outside your verified perimeter. Ensure sender authenticity before releasing sensitive credentials or executing files.'}
          {overallRiskLevel === 'safe' &&
            'Clean: Sender domain authentication succeeded (SPF/DKIM/DMARC) and all embedded links match their verified web destinations.'}
        </p>

        {/* Heuristic Signals List */}
        {heuristicSignals.length > 0 && (
          <div className="bg-slate-950/40 rounded-lg p-2.5 border border-white/5">
            <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5 flex items-center gap-1">
              <AlertTriangle className="w-3 h-3 text-amber-400" />
              <span>Identified Risk Indicators ({heuristicSignals.length}):</span>
            </div>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-1 text-[11.5px] text-slate-300">
              {heuristicSignals.map((signal, idx) => (
                <li key={idx} className="flex items-start gap-1.5">
                  <span className="text-red-400 text-xs leading-none mt-0.5">•</span>
                  <span>{signal}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Gemini AI Analysis Box if present */}
        {aiAnalysis && (
          <div className="bg-indigo-950/30 border border-indigo-500/30 rounded-lg p-3 text-xs text-indigo-100">
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-1.5 font-semibold text-indigo-300">
                <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                <span>Gemini Threat Intelligence Analysis</span>
              </div>
              <span className="text-[11px] px-2 py-0.5 rounded bg-indigo-900/60 border border-indigo-700 text-indigo-200">
                Category: {aiAnalysis.threatCategory}
              </span>
            </div>
            <p className="text-slate-300 leading-relaxed mb-2">{aiAnalysis.reasoning}</p>
            {aiAnalysis.socialEngineeringTactics?.length > 0 && (
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[11px] text-indigo-300 font-medium">Tactics detected:</span>
                {aiAnalysis.socialEngineeringTactics.map((tactic, i) => (
                  <span
                    key={i}
                    className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-900/40 border border-indigo-700/50 text-indigo-200"
                  >
                    {tactic}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Quick Action Footer */}
        <div className="pt-2 flex items-center justify-between flex-wrap gap-2 text-[11px]">
          <span className="text-slate-400 flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5 text-sky-400" />
            <span>Gmail Phishing Guard Content Protection active</span>
          </span>

          <div className="flex items-center gap-2">
            <button
              id="report-phishing-action-btn"
              onClick={onReportPhishing}
              className={`px-2.5 py-1 rounded text-xs font-medium flex items-center gap-1 transition-colors ${
                reported
                  ? 'bg-emerald-900/60 text-emerald-300 border border-emerald-700'
                  : 'bg-red-900/40 hover:bg-red-900/70 text-red-200 border border-red-800 cursor-pointer'
              }`}
            >
              <Flag className="w-3 h-3" />
              <span>{reported ? 'Reported to Security Team' : 'Report Phishing'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

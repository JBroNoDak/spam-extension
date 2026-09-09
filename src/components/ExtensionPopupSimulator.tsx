import React, { useState } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Sliders,
  Plus,
  Trash2,
  X,
  Search,
} from 'lucide-react';
import { analyzeLink } from '../utils/phishingScanner';

interface ExtensionPopupSimulatorProps {
  onClose: () => void;
}

export const ExtensionPopupSimulator: React.FC<ExtensionPopupSimulatorProps> = ({ onClose }) => {
  const [enabled, setEnabled] = useState(true);
  const [sensitivity, setSensitivity] = useState<'strict' | 'balanced' | 'permissive'>('balanced');
  const [whitelist, setWhitelist] = useState<string[]>(['company.com', 'trusted-partner.org']);
  const [newDomain, setNewDomain] = useState('');
  const [testUrl, setTestUrl] = useState('');
  const [testResult, setTestResult] = useState<any>(null);

  const handleAddDomain = () => {
    const val = newDomain.trim().toLowerCase();
    if (val && !whitelist.includes(val)) {
      setWhitelist([...whitelist, val]);
      setNewDomain('');
    }
  };

  const handleRemoveDomain = (d: string) => {
    setWhitelist(whitelist.filter((x) => x !== d));
  };

  const handleCheckUrl = () => {
    if (testUrl.trim()) {
      const res = analyzeLink(testUrl.trim(), testUrl.trim());
      setTestResult(res);
    }
  };

  return (
    <div
      id="popup-simulator-backdrop"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs"
      onClick={onClose}
    >
      <div
        id="popup-simulator-dialog"
        className="w-[360px] bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-4 text-slate-100 space-y-3"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Popup Header */}
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-sky-400" />
            <span className="font-bold text-xs tracking-wide text-white">Gmail Phishing Guard</span>
          </div>
          <div className="flex items-center gap-2">
            <span
              className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                enabled ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40' : 'bg-red-950 text-red-300 border border-red-500/40'
              }`}
            >
              {enabled ? '● ACTIVE' : '○ PAUSED'}
            </span>
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Protection Toggle */}
        <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-semibold text-slate-200">Real-Time In-DOM Scanning</div>
            <div className="text-[10px] text-slate-400">Scans links & attachments in Gmail</div>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-sky-600"></div>
          </label>
        </div>

        {/* Sensitivity Selector */}
        <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800 space-y-1.5">
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
            Detection Sensitivity
          </div>
          <div className="grid grid-cols-3 gap-1.5 text-xs font-medium">
            {(['strict', 'balanced', 'permissive'] as const).map((lvl) => (
              <button
                key={lvl}
                onClick={() => setSensitivity(lvl)}
                className={`py-1 rounded-lg capitalize text-xs transition-colors cursor-pointer ${
                  sensitivity === lvl
                    ? 'bg-sky-600 text-white font-semibold'
                    : 'bg-slate-900 text-slate-400 hover:bg-slate-800'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>
        </div>

        {/* Quick URL Reputation Tester */}
        <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800 space-y-2">
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
            Quick Link Inspector
          </div>
          <div className="flex gap-1.5">
            <input
              type="text"
              value={testUrl}
              onChange={(e) => setTestUrl(e.target.value)}
              placeholder="e.g. http://accounts-googIe.com"
              className="flex-1 px-2.5 py-1 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500"
            />
            <button
              onClick={handleCheckUrl}
              className="px-2.5 py-1 bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold rounded-lg transition-colors cursor-pointer"
            >
              Test
            </button>
          </div>

          {testResult && (
            <div
              className={`p-2 rounded-lg text-[11px] border ${
                testResult.riskLevel === 'critical'
                  ? 'bg-red-950/30 border-red-500/50 text-red-200'
                  : testResult.riskLevel === 'warning'
                  ? 'bg-amber-950/30 border-amber-500/50 text-amber-200'
                  : 'bg-emerald-950/30 border-emerald-500/50 text-emerald-200'
              }`}
            >
              <div className="font-bold uppercase tracking-wider text-[10px]">
                Verdict: {testResult.riskLevel} (Score {testResult.score}/100)
              </div>
              {testResult.issues.map((iss: string, i: number) => (
                <div key={i} className="mt-0.5">• {iss}</div>
              ))}
            </div>
          )}
        </div>

        {/* Whitelist Manager */}
        <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800 space-y-2">
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
            Trusted External Domains Whitelist
          </div>
          <div className="flex gap-1.5">
            <input
              type="text"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="e.g. client-corp.com"
              className="flex-1 px-2.5 py-1 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-sky-500"
            />
            <button
              onClick={handleAddDomain}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg border border-slate-700 transition-colors cursor-pointer"
            >
              Add
            </button>
          </div>

          <div className="flex flex-wrap gap-1.5 max-h-20 overflow-y-auto">
            {whitelist.map((d) => (
              <span
                key={d}
                className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] text-slate-300 flex items-center gap-1.5"
              >
                <span>{d}</span>
                <button
                  onClick={() => handleRemoveDomain(d)}
                  className="text-slate-500 hover:text-red-400 cursor-pointer"
                >
                  ×
                </button>
              </span>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="text-center text-[10px] text-slate-500 pt-1">
          Chrome Manifest V3 Extension Preview
        </div>
      </div>
    </div>
  );
};

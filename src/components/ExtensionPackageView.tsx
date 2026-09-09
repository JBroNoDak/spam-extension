import React, { useState, useEffect } from 'react';
import {
  Download,
  Copy,
  Check,
  Code2,
  FileText,
  Shield,
  Layers,
  ExternalLink,
  ArrowLeft,
  CheckCircle2,
  Terminal,
} from 'lucide-react';
import { downloadExtensionZip } from '../utils/zipGenerator';

interface ExtensionPackageViewProps {
  onBack: () => void;
}

export const ExtensionPackageView: React.FC<ExtensionPackageViewProps> = ({ onBack }) => {
  const [selectedFile, setSelectedFile] = useState<string>('manifest.json');
  const [fileContent, setFileContent] = useState<string>('Loading...');
  const [isDownloading, setIsDownloading] = useState(false);
  const [copied, setCopied] = useState(false);

  const files = [
    { name: 'manifest.json', desc: 'Manifest V3 configuration, permissions, host rules', icon: '⚙️' },
    { name: 'content.js', desc: 'Gmail DOM observer, link and attachment threat scanner', icon: '📜' },
    { name: 'content.css', desc: 'Injected color-coded badges, banners & popover styling', icon: '🎨' },
    { name: 'background.js', desc: 'Service worker managing settings & threat cache', icon: '⚡' },
    { name: 'popup.html', desc: 'Toolbar popup UI for active scanning & whitelist', icon: '🖥️' },
    { name: 'popup.js', desc: 'Popup controller & domain whitelist storage', icon: '🎛️' },
    { name: 'README.md', desc: 'Step-by-step installation & architecture overview', icon: '📖' },
  ];

  useEffect(() => {
    fetch(`/extension/${selectedFile}`)
      .then((res) => res.text())
      .then((text) => setFileContent(text))
      .catch(() => setFileContent('// Failed to load file content.'));
  }, [selectedFile]);

  const handleDownload = async () => {
    setIsDownloading(true);
    try {
      await downloadExtensionZip();
    } catch (e) {
      console.error(e);
    } finally {
      setIsDownloading(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(fileContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="h-full flex flex-col bg-slate-950 text-slate-100 overflow-y-auto">
      {/* Top Header */}
      <div className="h-14 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between px-4 flex-shrink-0">
        <button
          onClick={onBack}
          className="flex items-center gap-2 text-xs text-slate-300 hover:text-white px-2.5 py-1.5 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Gmail Inbox</span>
        </button>

        <button
          onClick={handleDownload}
          disabled={isDownloading}
          className="flex items-center gap-2 px-4 py-1.5 rounded-xl bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow transition-colors disabled:opacity-50 cursor-pointer"
        >
          <Download className="w-4 h-4" />
          <span>{isDownloading ? 'Packaging...' : 'Download Extension (.zip)'}</span>
        </button>
      </div>

      <div className="flex-1 p-4 md:p-8 max-w-6xl mx-auto w-full space-y-6">
        {/* Title and Intro */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Shield className="w-6 h-6 text-sky-400" />
              <h1 className="text-xl md:text-2xl font-bold text-white tracking-tight">
                Chrome Extension Package (Manifest V3)
              </h1>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Ready-to-install Chrome Extension for Gmail. Scans external emails, flags phishing attempts, and highlights suspicious links and attachments with color-coded warnings.
            </p>
          </div>

          <button
            onClick={handleDownload}
            disabled={isDownloading}
            className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-sky-600 to-indigo-600 hover:from-sky-500 hover:to-indigo-500 text-white text-xs font-bold shadow-lg transition-all cursor-pointer"
          >
            <Download className="w-4 h-4" />
            <span>{isDownloading ? 'Generating ZIP...' : 'Download Complete Extension (.zip)'}</span>
          </button>
        </div>

        {/* 3-Step Installation Guide */}
        <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-5 space-y-3">
          <div className="flex items-center gap-2 text-xs font-bold text-sky-400 uppercase tracking-wider">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>How to Load into Google Chrome in 3 Steps:</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1 text-xs">
            <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800 space-y-1">
              <div className="font-bold text-slate-200 flex items-center gap-1.5">
                <span className="w-5 h-5 rounded-full bg-sky-950 text-sky-400 border border-sky-600 flex items-center justify-center text-[10px]">
                  1
                </span>
                <span>Download & Unzip</span>
              </div>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Click <strong>"Download Complete Extension (.zip)"</strong> and extract the files into a folder on your computer.
              </p>
            </div>

            <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800 space-y-1">
              <div className="font-bold text-slate-200 flex items-center gap-1.5">
                <span className="w-5 h-5 rounded-full bg-sky-950 text-sky-400 border border-sky-600 flex items-center justify-center text-[10px]">
                  2
                </span>
                <span>Open Chrome Extensions</span>
              </div>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Go to <code className="text-sky-300 bg-slate-900 px-1 py-0.5 rounded">chrome://extensions</code> in Chrome and switch on <strong>Developer mode</strong> in the top right.
              </p>
            </div>

            <div className="bg-slate-950/80 p-3.5 rounded-xl border border-slate-800 space-y-1">
              <div className="font-bold text-slate-200 flex items-center gap-1.5">
                <span className="w-5 h-5 rounded-full bg-sky-950 text-sky-400 border border-sky-600 flex items-center justify-center text-[10px]">
                  3
                </span>
                <span>Load Unpacked</span>
              </div>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Click <strong>"Load unpacked"</strong>, select the unzipped folder, and open Gmail! The guard immediately monitors your inbox.
              </p>
            </div>
          </div>
        </div>

        {/* Reload & Whitelist Instructions Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-slate-900/90 rounded-2xl border border-sky-900/40 p-4 space-y-2">
            <div className="flex items-center gap-2 text-xs font-bold text-sky-400 uppercase tracking-wider">
              <span>🔄 How to Reload Extension After Updates</span>
            </div>
            <ol className="text-xs text-slate-300 space-y-1.5 pl-4 list-decimal leading-relaxed">
              <li>Open a new tab in Google Chrome and go to <code className="text-sky-300 bg-slate-950 px-1 py-0.5 rounded font-mono">chrome://extensions</code></li>
              <li>Ensure <strong>Developer mode</strong> toggle (top right corner) is <strong>ON</strong>.</li>
              <li>Locate <strong>Gmail Phishing Guard</strong> in your list of extensions.</li>
              <li>Click the <strong>🔄 Reload (circular arrow icon)</strong> on the extension card.</li>
              <li>Switch back to your <strong>Gmail tab</strong> and press <kbd className="bg-slate-800 px-1.5 py-0.5 rounded text-[11px] font-mono border border-slate-700">Ctrl + R</kbd> (or <kbd className="bg-slate-800 px-1.5 py-0.5 rounded text-[11px] font-mono border border-slate-700">Cmd + R</kbd>) to refresh!</li>
            </ol>
          </div>

          <div className="bg-slate-900/90 rounded-2xl border border-emerald-900/40 p-4 space-y-2">
            <div className="flex items-center gap-2 text-xs font-bold text-emerald-400 uppercase tracking-wider">
              <span>🏢 Stop Internal Emails From Being Flagged</span>
            </div>
            <div className="text-xs text-slate-300 space-y-1.5 leading-relaxed">
              <p>
                To designate your company domain (e.g. <code className="text-emerald-300 bg-slate-950 px-1 py-0.5 rounded font-mono">rks.io</code>) as internal:
              </p>
              <ol className="pl-4 list-decimal space-y-1 text-slate-400">
                <li>Click the <strong>🛡️ Gmail Phishing Guard icon</strong> in your Chrome extensions bar.</li>
                <li>In <strong>Trusted & Internal Domains</strong>, type your domain (e.g., <span className="text-white font-mono">rks.io</span>) and click <strong>+ Add</strong>.</li>
                <li>Click <strong>🔄 Apply Whitelist & Rescan Gmail</strong>.</li>
                <li>Emails from colleagues will now display a green <strong className="text-emerald-400">🏢 INTERNAL</strong> verified badge with zero false-alarm external warnings.</li>
              </ol>
            </div>
          </div>
        </div>

        {/* Source Code Explorer */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          {/* File Selector Sidebar */}
          <div className="lg:col-span-1 bg-slate-900 rounded-2xl border border-slate-800 p-3 space-y-1">
            <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider px-2 py-1 mb-1">
              Extension Files
            </div>
            {files.map((file) => (
              <button
                key={file.name}
                onClick={() => setSelectedFile(file.name)}
                className={`w-full text-left px-3 py-2 rounded-xl text-xs transition-colors flex items-start gap-2.5 cursor-pointer ${
                  selectedFile === file.name
                    ? 'bg-sky-950/80 text-sky-200 border border-sky-600/50 font-semibold'
                    : 'text-slate-300 hover:bg-slate-800/60'
                }`}
              >
                <span className="text-sm">{file.icon}</span>
                <div className="overflow-hidden">
                  <div className="font-mono text-xs truncate">{file.name}</div>
                  <div className="text-[10px] text-slate-400 truncate">{file.desc}</div>
                </div>
              </button>
            ))}
          </div>

          {/* Code Viewer */}
          <div className="lg:col-span-3 bg-slate-900 rounded-2xl border border-slate-800 flex flex-col overflow-hidden">
            <div className="h-11 border-b border-slate-800 bg-slate-950/60 px-4 flex items-center justify-between">
              <div className="flex items-center gap-2 font-mono text-xs text-slate-200">
                <Code2 className="w-4 h-4 text-sky-400" />
                <span>/extension/{selectedFile}</span>
              </div>

              <button
                onClick={handleCopy}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors cursor-pointer"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy Code'}</span>
              </button>
            </div>

            <div className="p-4 bg-slate-950/90 overflow-x-auto max-h-[500px]">
              <pre className="font-mono text-xs text-slate-300 leading-relaxed">
                <code>{fileContent}</code>
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

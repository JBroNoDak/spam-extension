import React, { useState } from 'react';
import { SAMPLE_EMAILS } from './data/sampleEmails';
import { EmailMessage } from './types';
import { GmailSimulator } from './components/GmailSimulator';
import { CustomEmailScanner } from './components/CustomEmailScanner';
import { ExtensionPackageView } from './components/ExtensionPackageView';
import { ExtensionPopupSimulator } from './components/ExtensionPopupSimulator';
import {
  Shield,
  Download,
  Sparkles,
  Inbox,
  Settings,
  HelpCircle,
  ExternalLink,
} from 'lucide-react';

export default function App() {
  const [view, setView] = useState<'simulator' | 'custom-scanner' | 'extension-package'>('simulator');
  const [emails, setEmails] = useState<EmailMessage[]>(SAMPLE_EMAILS);
  const [showPopupModal, setShowPopupModal] = useState(false);

  const handleAddEmailToInbox = (newEmail: EmailMessage) => {
    setEmails([newEmail, ...emails]);
    setView('simulator');
  };

  return (
    <div className="flex flex-col h-screen w-screen bg-slate-950 text-slate-100 font-sans overflow-hidden">
      {/* Universal Top Application Bar */}
      <nav className="h-12 bg-slate-950 border-b border-slate-800/80 px-4 flex items-center justify-between flex-shrink-0 z-30">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 font-bold text-sm tracking-tight text-white">
            <div className="w-6 h-6 rounded-lg bg-sky-500/20 border border-sky-400/40 flex items-center justify-center text-sky-400">
              <Shield className="w-3.5 h-3.5" />
            </div>
            <span>Gmail Phishing Guard</span>
          </div>

          <div className="h-4 w-px bg-slate-800 hidden sm:block" />

          {/* Navigation Tabs */}
          <div className="flex items-center gap-1 text-xs">
            <button
              id="nav-simulator-tab"
              onClick={() => setView('simulator')}
              className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer ${
                view === 'simulator'
                  ? 'bg-slate-800 text-sky-300 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Inbox className="w-3.5 h-3.5" />
              <span>Live Gmail Simulator</span>
            </button>

            <button
              id="nav-custom-scanner-tab"
              onClick={() => setView('custom-scanner')}
              className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer ${
                view === 'custom-scanner'
                  ? 'bg-slate-800 text-sky-300 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5 text-sky-400" />
              <span>Email Testbench</span>
            </button>

            <button
              id="nav-extension-package-tab"
              onClick={() => setView('extension-package')}
              className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer ${
                view === 'extension-package'
                  ? 'bg-slate-800 text-sky-300 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Download className="w-3.5 h-3.5 text-emerald-400" />
              <span>Extension Code & Download (.zip)</span>
            </button>
          </div>
        </div>

        {/* Right Action Icons */}
        <div className="flex items-center gap-2 text-xs">
          <button
            id="open-extension-popup-btn"
            onClick={() => setShowPopupModal(true)}
            title="Preview Chrome Toolbar Popup"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors cursor-pointer"
          >
            <Settings className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden md:inline">Extension Settings</span>
          </button>
        </div>
      </nav>

      {/* Main Viewport */}
      <main className="flex-1 overflow-hidden">
        {view === 'simulator' && (
          <GmailSimulator
            emails={emails}
            onOpenCustomScanner={() => setView('custom-scanner')}
            onOpenExtensionPackage={() => setView('extension-package')}
          />
        )}

        {view === 'custom-scanner' && (
          <CustomEmailScanner
            onBack={() => setView('simulator')}
            onAddToInbox={handleAddEmailToInbox}
          />
        )}

        {view === 'extension-package' && (
          <ExtensionPackageView onBack={() => setView('simulator')} />
        )}
      </main>

      {/* Extension Toolbar Popup Simulator Modal */}
      {showPopupModal && (
        <ExtensionPopupSimulator onClose={() => setShowPopupModal(false)} />
      )}
    </div>
  );
}

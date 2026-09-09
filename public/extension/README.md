# Gmail Phishing Guard - Chrome Extension (Manifest V3)

Scans incoming external Gmail emails for phishing, executive impersonation, credential theft, and malware delivery.

## Key Features
- **External Email Detection**: Flags emails originating outside your trusted domain perimeter.
- **Color-Coded Warning System**:
  - 🔴 **Critical (Red)**: Lookalike typosquatted domains (e.g. `googIe.com`, `paypaI.com`), display text vs URL mismatches, raw IP address links, double-extension executables (`.pdf.exe`), direct malware payloads (`.exe`, `.scr`, `.bat`, `.iso`).
  - 🟠 **Suspicious (Amber)**: Obfuscated shorteners (`bit.ly`, `tinyurl`), macro-enabled Office files (`.docm`, `.xlsm`), unverified zip archives, high-urgency credential lures.
  - 🟡 **Caution (Yellow)**: First-time external sender, unencrypted HTTP links.
  - 🟢 **Safe (Green)**: Verified sender, clean link reputations, safe attachments.
- **In-Email Link Inspection**: Highlights links directly in the email body with colored badges and provides safe inspection cards before clicking.
- **Attachment Threat Scanner**: Injects risk indicators onto Gmail attachment cards.
- **Interactive Security Banner**: Injects a clear warning summary at the top of external emails.

## How to Install in Google Chrome
1. Extract or download this `extension` folder onto your computer.
2. In Google Chrome, navigate to `chrome://extensions/` in your address bar.
3. Toggle on **Developer mode** in the top-right corner.
4. Click **Load unpacked** in the top-left corner.
5. Select this folder containing `manifest.json`.
6. Open or refresh [Gmail](https://mail.google.com). The shield is now actively protecting your inbox!

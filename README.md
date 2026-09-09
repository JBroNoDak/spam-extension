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

## How to Reload After Updating Code or Publishing Changes
Whenever you update code or download a new ZIP package:
1. Replace or update the files in your unpacked extension folder on your computer.
2. Open `chrome://extensions/` in Chrome.
3. Find **"Gmail Phishing Guard"** in your list of extensions.
4. Click the **🔄 Reload (circular arrow icon)** on the extension card.
5. Switch to your Gmail tab and press **`Ctrl + R`** (or **`Cmd + R`** on Mac) to refresh the page.

## Internal Organization & Whitelist Configuration
To ensure your internal company emails (e.g., `@rks.io`) are recognized as internal and not flagged as external:
1. Click the **🛡️ Gmail Phishing Guard** icon in your Chrome toolbar.
2. Under **"Trusted & Internal Domains (Whitelist)"**, enter your company domain (e.g. `rks.io` or `yourdomain.com`).
3. Click **"+ Add"**, then click **"🔄 Apply Whitelist & Rescan Gmail"**.
4. The extension automatically syncs in real-time across your open Gmail tabs:
   - Internal emails will display a green `🏢 INTERNAL (domain)` badge.
   - External sender caution warnings will be removed for all matching emails.
   - Any links pointing to your internal domain will be verified as safe.

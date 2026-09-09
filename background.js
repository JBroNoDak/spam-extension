/**
 * Gmail Phishing Guard - Chrome Background Service Worker
 */

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.set({
    enabled: true,
    sensitivity: 'balanced', // 'strict', 'balanced', 'permissive'
    whitelist: ['company.com', 'trusted-partner.org'],
    interceptCriticalClicks: true,
    stats: {
      emailsScanned: 0,
      threatsBlocked: 0,
      linksInspected: 0,
      attachmentsFlagged: 0,
    },
  });
  console.log('Gmail Phishing Guard extension installed and initialized.');
});

// Listener for messages from content scripts or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'GET_CONFIG') {
    chrome.storage.sync.get(['enabled', 'sensitivity', 'whitelist', 'stats'], (items) => {
      sendResponse(items);
    });
    return true; // Keep channel open for async response
  }

  if (request.type === 'UPDATE_STATS') {
    chrome.storage.sync.get(['stats'], (res) => {
      const currentStats = res.stats || { emailsScanned: 0, threatsBlocked: 0, linksInspected: 0, attachmentsFlagged: 0 };
      const newStats = {
        emailsScanned: currentStats.emailsScanned + (request.data.scanned || 0),
        threatsBlocked: currentStats.threatsBlocked + (request.data.threats || 0),
        linksInspected: currentStats.linksInspected + (request.data.links || 0),
        attachmentsFlagged: currentStats.attachmentsFlagged + (request.data.attachments || 0),
      };
      chrome.storage.sync.set({ stats: newStats });
      sendResponse({ success: true, stats: newStats });
    });
    return true;
  }
});

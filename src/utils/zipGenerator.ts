import JSZip from 'jszip';

export async function downloadExtensionZip(): Promise<void> {
  const zip = new JSZip();

  // Extension files definition
  const manifestContent = await fetchText('/extension/manifest.json');
  const contentJsContent = await fetchText('/extension/content.js');
  const contentCssContent = await fetchText('/extension/content.css');
  const backgroundJsContent = await fetchText('/extension/background.js');
  const popupHtmlContent = await fetchText('/extension/popup.html');
  const popupJsContent = await fetchText('/extension/popup.js');
  const readmeContent = await fetchText('/extension/README.md');

  zip.file('manifest.json', manifestContent);
  zip.file('content.js', contentJsContent);
  zip.file('content.css', contentCssContent);
  zip.file('background.js', backgroundJsContent);
  zip.file('popup.html', popupHtmlContent);
  zip.file('popup.js', popupJsContent);
  zip.file('README.md', readmeContent);

  const blob = await zip.generateAsync({ type: 'blob' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'gmail-phishing-guard-extension.zip';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function fetchText(path: string): Promise<string> {
  try {
    const res = await fetch(path);
    if (res.ok) {
      return await res.text();
    }
  } catch (e) {
    console.error(`Failed to fetch ${path}:`, e);
  }
  return '';
}

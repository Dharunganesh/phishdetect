// Content script for injecting warnings into pages

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'showWarning') {
    injectPhishingWarning(message.data);
  } else if (message.action === 'ping') {
    // Respond to ping to indicate content script is loaded
    sendResponse({ status: 'ready' });
  }
  return true; // Required for async response
});

// Inject phishing warning banner
function injectPhishingWarning(data) {
  // Check if banner already exists
  if (document.getElementById('phishguard-warning')) {
    return;
  }
  
  // Create warning banner
  const banner = document.createElement('div');
  banner.id = 'phishguard-warning';
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background-color: #dc3545;
    color: white;
    padding: 15px;
    text-align: center;
    z-index: 9999;
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
    font-size: 16px;
    display: flex;
    justify-content: center;
    align-items: center;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
  `;
  
  // Calculate confidence percentage
  const confidencePct = Math.round(data.confidence * 100);
  
  // Create content for banner
  banner.innerHTML = `
    <div style="display: flex; align-items: center; max-width: 800px;">
      <div style="font-size: 24px; margin-right: 10px;">⚠️</div>
      <div style="flex-grow: 1; text-align: left;">
        <strong style="font-size: 18px;">Phishing Warning!</strong>
        <p style="margin: 5px 0 0 0;">PhishGuard has detected that this website may be a phishing attempt (${confidencePct}% confidence).</p>
      </div>
      <div>
        <button id="phishguard-dismiss" style="background-color: rgba(255,255,255,0.2); border: none; color: white; padding: 5px 10px; border-radius: 3px; cursor: pointer; margin-right: 5px;">Dismiss</button>
        <button id="phishguard-details" style="background-color: white; border: none; color: #dc3545; padding: 5px 10px; border-radius: 3px; cursor: pointer; font-weight: bold;">Details</button>
      </div>
    </div>
  `;
  
  // Add banner to page
  document.body.prepend(banner);
  
  // Add event listeners to buttons
  document.getElementById('phishguard-dismiss').addEventListener('click', function() {
    banner.style.display = 'none';
  });
  
  document.getElementById('phishguard-details').addEventListener('click', function() {
    chrome.runtime.sendMessage({ action: 'openPopup' });
  });
  
  // Auto-hide after 10 seconds
  setTimeout(() => {
    if (banner.parentNode) {
      banner.style.opacity = '0';
      banner.style.transition = 'opacity 1s ease-in-out';
      setTimeout(() => {
        if (banner.parentNode) {
          banner.parentNode.removeChild(banner);
        }
      }, 1000);
    }
  }, 10000);
}

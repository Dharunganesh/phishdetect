// API configuration
// For development, use localhost; for production, update to the deployed URL
const API_BASE_URL = window.location.hostname === 'localhost' 
  ? 'http://localhost:5000/api'
  : 'https://web-production-0d15.up.railway.app/api';

// Store for currently active warnings
let activeWarnings = {};

// When installed or updated
chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishGuard extension installed/updated');
  
  // Clear any stored data
  chrome.storage.local.clear();
});

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'phishingDetected') {
    // Show warning notification
    showPhishingWarning(message.url, message.data);
  } else if (message.action === 'openPopup') {
    // Open the extension popup
    chrome.action.openPopup();
  }
  
  return true; // Required for async response
});

// When user navigates to a new page in any tab
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only check completed main frame loads with URLs
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    checkUrl(tab.url, tabId);
  }
});

// Check if URL is phishing
async function checkUrl(url, tabId) {
  try {
    // Check in storage cache first
    const cachedResult = await getCachedResult(url);
    if (cachedResult) {
      // If it's phishing, show warning
      if (cachedResult.is_phishing) {
        showPhishingWarning(url, cachedResult, tabId);
      }
      return;
    }
    
    // Send request to backend API
    const response = await fetch(`${API_BASE_URL}/check_url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url }),
    });
    
    if (!response.ok) {
      throw new Error('API request failed');
    }
    
    const data = await response.json();
    
    // Cache the result
    cacheResult(url, data);
    
    // If it's phishing, show warning
    if (data.is_phishing) {
      showPhishingWarning(url, data, tabId);
    }
    
  } catch (error) {
    console.error('Error checking URL:', error);
  }
}

// Get cached result from Chrome storage
async function getCachedResult(url) {
  return new Promise((resolve) => {
    chrome.storage.local.get([url], function(result) {
      const cachedData = result[url];
      
      // If no cache or cache older than 1 hour, return null
      if (!cachedData || Date.now() - cachedData.timestamp > 3600000) {
        resolve(null);
        return;
      }
      
      resolve(cachedData.result);
    });
  });
}

// Cache the result in Chrome storage
function cacheResult(url, data) {
  const cacheData = {
    url: url,
    result: data,
    timestamp: Date.now()
  };
  
  chrome.storage.local.set({[url]: cacheData});
}

// Show phishing warning
function showPhishingWarning(url, data, tabId) {
  // Skip if already warned for this URL
  if (activeWarnings[url]) {
    return;
  }
  
  // Mark as actively warned
  activeWarnings[url] = true;
  
  // Calculate confidence percentage
  const confidencePct = Math.round(data.confidence * 100);
  
  // Create notification
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.svg',
    title: '⚠️ Phishing Warning!',
    message: `The site "${url}" appears to be a phishing attempt (${confidencePct}% confidence).`,
    priority: 2,
    buttons: [
      { title: 'View Details' },
      { title: 'Close' }
    ]
  }, (notificationId) => {
    // Store notification ID with URL
    activeWarnings[url] = notificationId;
    
    // Automatically remove active warning after 30 seconds
    setTimeout(() => {
      delete activeWarnings[url];
    }, 30000);
  });
  
  // If tabId provided, inject warning into page
  if (tabId) {
    // Check if content script is ready by sending a message
    chrome.tabs.sendMessage(tabId, { action: 'ping' }, response => {
      if (chrome.runtime.lastError) {
        // Content script not ready, inject it manually first
        chrome.scripting.executeScript({
          target: { tabId: tabId },
          files: ['content.js']
        }).then(() => {
          // Now send the warning message
          setTimeout(() => {
            chrome.tabs.sendMessage(tabId, {
              action: 'showWarning',
              data: data
            });
          }, 100);
        }).catch(err => {
          console.error('Error injecting content script:', err);
        });
      } else {
        // Content script is ready, send the warning
        chrome.tabs.sendMessage(tabId, {
          action: 'showWarning',
          data: data
        });
      }
    });
  }
}

// Listen for notification button clicks
chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
  // Find which URL this notification was for
  const url = Object.keys(activeWarnings).find(key => activeWarnings[key] === notificationId);
  
  if (buttonIndex === 0) {
    // View Details - open popup
    chrome.action.openPopup();
  }
  
  // Clean up
  chrome.notifications.clear(notificationId);
  if (url) {
    delete activeWarnings[url];
  }
});

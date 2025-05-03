// API configuration
// For development, use localhost; for production, update to the deployed URL
const API_BASE_URL = window.location.hostname === 'localhost' 
  ? 'http://localhost:5000/api'
  : 'https://web-production-0d15.up.railway.app/api';

// DOM elements
let currentUrl = '';
let scanResult = null;

// Initialize popup
document.addEventListener('DOMContentLoaded', function() {
  // Get the current tab URL
  getCurrentTabUrl().then(url => {
    currentUrl = url;
    document.getElementById('current-url').textContent = url;
    checkUrl(url);
    loadRecentPhishing();
  });
  
  // Set up event listeners
  document.getElementById('rescan-btn').addEventListener('click', () => {
    resetUI();
    checkUrl(currentUrl, true);
  });
  
  document.getElementById('report-btn').addEventListener('click', () => {
    reportPhishing(currentUrl);
  });
  
  document.getElementById('refresh-recent-btn').addEventListener('click', () => {
    loadRecentPhishing();
  });
});

// Get the current tab URL
async function getCurrentTabUrl() {
  return new Promise((resolve) => {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      resolve(tabs[0].url);
    });
  });
}

// Reset the UI to initial state
function resetUI() {
  document.getElementById('status-indicator').className = 'status-indicator status-loading me-2';
  document.getElementById('status-text').textContent = 'Checking...';
  document.getElementById('scan-details').classList.add('d-none');
  document.getElementById('action-container').classList.add('d-none');
  
  // Reset VirusTotal stats
  document.getElementById('vt-stats').innerHTML = '<span class="badge bg-danger" id="vt-malicious">0</span> / <span id="vt-total">0</span>';
}

// Check if a URL is a phishing attempt
async function checkUrl(url, forceCheck = false) {
  try {
    // Skip checking if not an HTTP/HTTPS URL
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      document.getElementById('status-indicator').className = 'status-indicator status-neutral me-2';
      document.getElementById('status-text').textContent = 'Not a web URL';
      return;
    }
    
    // Show checking state
    document.getElementById('status-indicator').className = 'status-indicator status-loading me-2';
    document.getElementById('status-text').textContent = 'Checking...';
    
    // Check in storage cache first if not forcing a check
    if (!forceCheck) {
      const cachedResult = await getCachedResult(url);
      if (cachedResult) {
        updateUI(cachedResult);
        return;
      }
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
    
    // Update the UI with the result
    updateUI(data);
    
    // If VirusTotal data is not available, poll for updates
    if (data.virustotal_positives === null && data.is_phishing) {
      pollForVirusTotalResults(url);
    }
    
  } catch (error) {
    console.error('Error checking URL:', error);
    document.getElementById('status-indicator').className = 'status-indicator status-error me-2';
    document.getElementById('status-text').textContent = 'Error checking URL';
  }
}

// Update the UI with the check result
function updateUI(data) {
  scanResult = data;
  const statusIndicator = document.getElementById('status-indicator');
  const statusText = document.getElementById('status-text');
  const scanDetails = document.getElementById('scan-details');
  const actionContainer = document.getElementById('action-container');
  
  // Show scan details
  scanDetails.classList.remove('d-none');
  actionContainer.classList.remove('d-none');
  
  // Update confidence
  const confidencePct = Math.round(data.confidence * 100);
  const mlConfidence = document.getElementById('ml-confidence');
  mlConfidence.style.width = `${confidencePct}%`;
  mlConfidence.textContent = `${confidencePct}%`;
  
  // Update VT stats if available
  if (data.virustotal_positives !== null && data.virustotal_total !== null) {
    document.getElementById('vt-malicious').textContent = data.virustotal_positives;
    document.getElementById('vt-total').textContent = data.virustotal_total;
  } else {
    document.getElementById('vt-stats').textContent = 'N/A';
  }
  
  // Update status based on result
  if (data.is_phishing) {
    statusIndicator.className = 'status-indicator status-danger me-2';
    statusText.textContent = 'Potential Phishing Site!';
    statusText.className = 'mb-0 text-danger fw-bold';
    
    // Notify background script to show warning
    chrome.runtime.sendMessage({
      action: 'phishingDetected',
      url: currentUrl,
      data: data
    });
    
  } else {
    statusIndicator.className = 'status-indicator status-safe me-2';
    statusText.textContent = 'Appears Safe';
    statusText.className = 'mb-0 text-success';
  }
}

// Cache the result in Chrome storage
function cacheResult(url, data) {
  const cacheData = {
    url: url,
    result: data,
    timestamp: Date.now()
  };
  
  chrome.storage.local.set({[url]: cacheData}, function() {
    console.log('Result cached for:', url);
  });
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

// Load recent phishing URLs
async function loadRecentPhishing() {
  try {
    const response = await fetch(`${API_BASE_URL}/recent_phishing`);
    
    if (!response.ok) {
      throw new Error('Failed to load recent detections');
    }
    
    const data = await response.json();
    
    const recentList = document.getElementById('recent-phishing-list');
    recentList.innerHTML = '';
    
    if (data.urls && data.urls.length > 0) {
      data.urls.forEach(item => {
        const li = document.createElement('li');
        li.className = 'list-group-item py-2';
        
        const urlText = document.createElement('p');
        urlText.className = 'mb-1 text-truncate small';
        urlText.style.maxWidth = '100%';
        urlText.title = item.url;
        urlText.textContent = item.url;
        
        const infoText = document.createElement('p');
        infoText.className = 'mb-0 text-muted small';
        
        const confidence = Math.round(item.ml_confidence * 100);
        infoText.textContent = `Confidence: ${confidence}% · Detected: ${new Date(item.created_at).toLocaleDateString()}`;
        
        li.appendChild(urlText);
        li.appendChild(infoText);
        li.addEventListener('click', () => {
          chrome.tabs.create({ url: item.url });
        });
        
        recentList.appendChild(li);
      });
    } else {
      const li = document.createElement('li');
      li.className = 'list-group-item text-center text-muted';
      li.innerHTML = '<small>No recent detections</small>';
      recentList.appendChild(li);
    }
    
  } catch (error) {
    console.error('Error loading recent phishing:', error);
    const recentList = document.getElementById('recent-phishing-list');
    recentList.innerHTML = '<li class="list-group-item text-center text-danger"><small>Error loading data</small></li>';
  }
}

// Poll for VirusTotal results and update UI
let pollingTimer = null;
async function pollForVirusTotalResults(url) {
  // Clear any existing timer
  if (pollingTimer) {
    clearTimeout(pollingTimer);
  }
  
  let attempts = 0;
  const maxAttempts = 5;
  
  async function checkForUpdates() {
    if (attempts >= maxAttempts) {
      console.log('Stopped polling for VirusTotal results after max attempts');
      return;
    }
    
    attempts++;
    
    try {
      console.log(`Polling for VirusTotal results (attempt ${attempts}/${maxAttempts})...`);
      
      // Check the URL again
      const response = await fetch(`${API_BASE_URL}/check_url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url }),
      });
      
      if (response.ok) {
        const data = await response.json();
        
        // If VirusTotal results are now available, update UI
        if (data.virustotal_positives !== null && data.virustotal_total !== null) {
          console.log('VirusTotal results received:', data.virustotal_positives, '/', data.virustotal_total);
          
          // Update the display
          document.getElementById('vt-malicious').textContent = data.virustotal_positives;
          document.getElementById('vt-total').textContent = data.virustotal_total;
          
          // Update the cached data
          cacheResult(url, data);
          
          // Update the scan result
          scanResult = data;
          
          // Stop polling
          return;
        }
      }
      
      // Schedule next poll attempt (increasing delay each time)
      const delay = 3000 + (attempts * 1000);
      pollingTimer = setTimeout(checkForUpdates, delay);
      
    } catch (error) {
      console.error('Error polling for VirusTotal results:', error);
      // Schedule retry despite error
      pollingTimer = setTimeout(checkForUpdates, 5000);
    }
  }
  
  // Start the polling process
  checkForUpdates();
}

// Report phishing URL to our backend API
async function reportPhishing(url) {
  try {
    // Show reporting in progress
    const reportBtn = document.getElementById('report-btn');
    const originalText = reportBtn.innerHTML;
    reportBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Reporting...';
    reportBtn.disabled = true;
    
    // Call the API to report this URL as phishing
    const response = await fetch(`${API_BASE_URL}/check_url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ 
        url: url,
        report: true,  // Flag to indicate this is a user report
        is_phishing: true  // User is reporting this as phishing
      }),
    });
    
    if (!response.ok) {
      throw new Error('Failed to report URL');
    }
    
    const data = await response.json();
    
    // Update cache with the new result
    cacheResult(url, data);
    
    // If UI is not already showing this as phishing, update it
    if (!scanResult?.is_phishing) {
      updateUI(data);
    }
    
    // Show success
    reportBtn.innerHTML = '<i class="fas fa-check"></i> Reported';
    reportBtn.classList.remove('btn-outline-danger');
    reportBtn.classList.add('btn-success');
    
    // Update recent phishing list
    loadRecentPhishing();
    
    // Reset after a delay
    setTimeout(() => {
      reportBtn.innerHTML = originalText;
      reportBtn.classList.remove('btn-success');
      reportBtn.classList.add('btn-outline-danger');
      reportBtn.disabled = false;
    }, 3000);
    
  } catch (error) {
    console.error('Error reporting phishing:', error);
    document.getElementById('report-btn').innerHTML = '<i class="fas fa-exclamation-circle"></i> Error';
    setTimeout(() => {
      document.getElementById('report-btn').innerHTML = '<i class="fas fa-exclamation-triangle"></i> Report Phishing';
      document.getElementById('report-btn').disabled = false;
    }, 3000);
  }
}


import os
import requests
import logging
import time
import base64
from urllib.parse import quote_plus

class VirusTotalAPI:
    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "2b0576adebba12a50a741aa50d436e37232410d10d9d38936da077b74d03c8e7")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.rate_limit_per_minute = 4
        self.last_request_time = 0
        self.max_retries = 3
        self.retry_delay = 5
        
    def check_url(self, url):
        if not self.api_key:
            logging.error("VirusTotal API key not set")
            return None
            
        try:
            # Properly encode URL
            encoded_url = quote_plus(url)
            
            # Submit URL with retries
            analysis_id = None
            for attempt in range(self.max_retries):
                analysis_id = self._submit_url(encoded_url)
                if analysis_id:
                    break
                time.sleep(self.retry_delay)
            
            if not analysis_id:
                logging.error(f"Failed to submit URL after {self.max_retries} attempts")
                return None
                
            # Wait for analysis with longer timeout
            timeout = 30  # seconds
            start_time = time.time()
            analysis_result = None
            
            while time.time() - start_time < timeout:
                analysis_result = self._get_analysis_result(analysis_id)
                if analysis_result:
                    status = analysis_result.get('status')
                    logging.info(f"Analysis status: {status}")
                    
                    if status == 'completed':
                        break
                    elif status == 'queued':
                        time.sleep(5)
                    else:
                        time.sleep(2)
            
            # Try to get report even if analysis times out
            report = self._get_url_report(encoded_url)
            if report:
                return report
                
            # If no report, try legacy endpoint
            legacy_report = self._get_legacy_report(encoded_url)
            if legacy_report:
                return legacy_report
                
            logging.warning(f"No results found for URL: {url}")
            return None
            
        except Exception as e:
            logging.error(f"Error checking URL: {e}")
            return None
    
    def _submit_url(self, url):
        self._respect_rate_limit()
        
        try:
            endpoint = f"{self.base_url}/urls"
            headers = {
                "x-apikey": self.api_key,
                "Content-Type": "application/x-www-form-urlencoded"
            }
            data = {"url": url}
            
            response = requests.post(endpoint, headers=headers, data=data)
            
            if response.status_code == 200:
                return response.json().get('data', {}).get('id')
            else:
                logging.error(f"Submit URL failed: {response.status_code}")
                return None
                
        except Exception as e:
            logging.error(f"Submit URL error: {e}")
            return None
    
    def _get_analysis_result(self, analysis_id):
        self._respect_rate_limit()
        
        try:
            endpoint = f"{self.base_url}/analyses/{analysis_id}"
            headers = {"x-apikey": self.api_key}
            
            response = requests.get(endpoint, headers=headers)
            
            if response.status_code == 200:
                return response.json().get('data', {}).get('attributes', {})
            return None
            
        except Exception as e:
            logging.error(f"Get analysis error: {e}")
            return None
    
    def _get_url_report(self, url):
        self._respect_rate_limit()
        
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            endpoint = f"{self.base_url}/urls/{url_id}"
            headers = {"x-apikey": self.api_key}
            
            response = requests.get(endpoint, headers=headers)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                attributes = data.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                return {
                    'harmless': stats.get('harmless', 0),
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'timeout': stats.get('timeout', 0),
                    'total': sum(stats.values()) or None,
                    'scan_date': attributes.get('last_analysis_date'),
                    'reputation': attributes.get('reputation', 0)
                }
            return None
            
        except Exception as e:
            logging.error(f"Get report error: {e}")
            return None
    
    def _get_legacy_report(self, url):
        """Fallback to legacy v2 API endpoint"""
        self._respect_rate_limit()
        
        try:
            endpoint = f"https://www.virustotal.com/vtapi/v2/url/report"
            params = {
                'apikey': self.api_key,
                'resource': url
            }
            
            response = requests.get(endpoint, params=params)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'harmless': data.get('harmless', 0),
                    'malicious': data.get('positives', 0),
                    'total': data.get('total', None),
                    'scan_date': data.get('scan_date'),
                    'reputation': 0
                }
            return None
            
        except Exception as e:
            logging.error(f"Legacy report error: {e}")
            return None
    
    def _respect_rate_limit(self):
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < (60 / self.rate_limit_per_minute):
            sleep_time = (60 / self.rate_limit_per_minute) - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()

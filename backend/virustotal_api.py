import os
import requests
import logging
import time

class VirusTotalAPI:
    def __init__(self):
        # Get API key from environment variable
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "2b0576adebba12a50a741aa50d436e37232410d10d9d38936da077b74d03c8e7")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.rate_limit_per_minute = 4  # Free tier limit
        self.last_request_time = 0
        
    def check_url(self, url):
        """
        Check a URL using VirusTotal API
        Returns: dict with detection results or None if error
        """
        if not self.api_key:
            logging.error("VirusTotal API key not set! Please configure VIRUSTOTAL_API_KEY in environment variables")
            return None
            
        # Rate limiting
        self._respect_rate_limit()
        
        try:
            # First, submit the URL for analysis
            analysis_id = self._submit_url(url)
            if not analysis_id:
                logging.error("Failed to get analysis ID from VirusTotal")
                return None
                
            # Wait for analysis to complete (with timeout)
            timeout = 60  # seconds - increased for better completion rate
            start_time = time.time()
            analysis_result = None
            
            while time.time() - start_time < timeout:
                analysis_result = self._get_analysis_result(analysis_id)
                if analysis_result:
                    status = analysis_result.get('status')
                    logging.info(f"VirusTotal analysis status: {status}")
                    if status == 'completed':
                        break
                    elif status == 'queued':
                        time.sleep(5)  # Longer wait for queued status
                    else:
                        time.sleep(2)  # Normal wait for other statuses
            
            if not analysis_result or analysis_result.get('status') != 'completed':
                logging.warning(f"VirusTotal analysis timed out for URL: {url}")
                return None
            
            # Get the URL report
            return self._get_url_report(url)
            
        except Exception as e:
            logging.error(f"Error checking URL with VirusTotal: {e}")
            return None
    
    def _respect_rate_limit(self):
        """Ensure we don't exceed the API rate limit"""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        # If less than rate limit, wait
        if time_since_last_request < (60 / self.rate_limit_per_minute):
            sleep_time = (60 / self.rate_limit_per_minute) - time_since_last_request
            time.sleep(sleep_time)
            
        self.last_request_time = time.time()
    
    def _submit_url(self, url):
        """Submit a URL for analysis"""
        endpoint = f"{self.base_url}/urls"
        headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {"url": url}
        
        response = requests.post(endpoint, headers=headers, data=data)
        
        if response.status_code == 200:
            result = response.json()
            return result.get('data', {}).get('id')
        else:
            logging.error(f"Error submitting URL to VirusTotal: {response.status_code}, {response.text}")
            return None
    
    def _get_analysis_result(self, analysis_id):
        """Get analysis result by ID"""
        endpoint = f"{self.base_url}/analyses/{analysis_id}"
        headers = {"x-apikey": self.api_key}
        
        response = requests.get(endpoint, headers=headers)
        
        if response.status_code == 200:
            return response.json().get('data', {}).get('attributes', {})
        else:
            logging.error(f"Error getting analysis from VirusTotal: {response.status_code}, {response.text}")
            return None
    
    def _get_url_report(self, url):
        """Get a URL report"""
        import base64
        
        # URL identifier is the base64 encoded URL
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
                'total': sum(stats.values()),
                'scan_date': attributes.get('last_analysis_date'),
                'reputation': attributes.get('reputation', 0),
                'categories': attributes.get('categories', {})
            }
        else:
            logging.error(f"Error getting URL report from VirusTotal: {response.status_code}, {response.text}")
            return None

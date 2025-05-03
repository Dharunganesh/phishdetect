import numpy as np
import re
import urllib.parse
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import os
import tldextract

class PhishingURLPredictor:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Try to load a pre-trained model if it exists
        try:
            if os.path.exists("phishing_model.joblib"):
                self.model = joblib.load("phishing_model.joblib")
                self.scaler = joblib.load("phishing_scaler.joblib")
                self.is_trained = True
                logging.info("Loaded pre-trained phishing detection model")
        except Exception as e:
            logging.warning(f"Could not load pre-trained model: {e}")
            # We'll train the model on first use if needed
    
    def extract_features(self, url):
        """Extract features from URL for phishing detection"""
        features = {}
        
        # Parse the URL
        parsed_url = urllib.parse.urlparse(url)
        extract_result = tldextract.extract(url)
        
        # Basic URL components
        features['url_length'] = len(url)
        features['domain_length'] = len(extract_result.domain)
        features['tld_length'] = len(extract_result.suffix) if extract_result.suffix else 0
        features['subdomain_length'] = len(extract_result.subdomain)
        features['path_length'] = len(parsed_url.path)
        features['query_length'] = len(parsed_url.query)
        
        # Number of specific characters
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_equals'] = url.count('=')
        features['num_at_symbols'] = url.count('@')
        features['num_ampersands'] = url.count('&')
        features['num_question_marks'] = url.count('?')
        features['num_percent'] = url.count('%')
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        # Security indicators
        features['has_https'] = int(parsed_url.scheme == 'https')
        features['has_ip_address'] = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))
        features['has_suspicious_words'] = int(
            bool(re.search(r'(login|signin|verify|secure|account|password|bank|paypal|ebay|update)', 
                          url.lower()))
        )
        
        # Convert features to a list in a consistent order
        feature_vector = [
            features['url_length'],
            features['domain_length'],
            features['tld_length'],
            features['subdomain_length'],
            features['path_length'],
            features['query_length'],
            features['num_dots'],
            features['num_hyphens'],
            features['num_underscores'],
            features['num_slashes'],
            features['num_equals'],
            features['num_at_symbols'],
            features['num_ampersands'],
            features['num_question_marks'],
            features['num_percent'],
            features['num_digits'],
            features['has_https'],
            features['has_ip_address'],
            features['has_suspicious_words']
        ]
        
        return np.array([feature_vector]), features
    
    def train_model(self, urls, labels):
        """Train the model with labeled data (URLs and corresponding phishing/non-phishing labels)"""
        features_list = []
        for url in urls:
            feature_vector, _ = self.extract_features(url)
            features_list.append(feature_vector[0])
        
        X = np.array(features_list)
        y = np.array(labels)
        
        # Scale features
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        # Train the model
        self.model.fit(X_scaled, y)
        self.is_trained = True
        
        # Save the model
        joblib.dump(self.model, "phishing_model.joblib")
        joblib.dump(self.scaler, "phishing_scaler.joblib")
        
        return self.model
    
    def predict(self, url):
        """Predict if a URL is a phishing attempt"""
        if not self.is_trained:
            # If not trained, use a simple heuristic approach until we have training data
            logging.warning("Model not yet trained, using heuristic prediction")
            # A simple heuristic: suspicious words and characteristics
            parsed_url = urllib.parse.urlparse(url)
            extract_result = tldextract.extract(url)
            
            suspicious = False
            confidence = 0.5  # Default neutral confidence
            
            # Check for common phishing indicators
            if bool(re.search(r'(login|signin|verify|secure|account|password|bank|paypal|ebay|update)', 
                             url.lower())):
                confidence += 0.1
                suspicious = True
                
            if bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)):
                confidence += 0.15
                suspicious = True
                
            if '@' in url:
                confidence += 0.2
                suspicious = True
                
            if parsed_url.scheme != 'https':
                confidence += 0.05
                suspicious = True
                
            if len(url) > 100:
                confidence += 0.05
                suspicious = True
                
            if len(extract_result.domain) > 20:
                confidence += 0.1
                suspicious = True
                
            if url.count('.') > 3:
                confidence += 0.05
                suspicious = True
                
            # Return prediction and confidence
            return suspicious, min(confidence, 0.95), {}
        
        # Extract features from the URL
        feature_vector, feature_dict = self.extract_features(url)
        
        # Scale the features
        X_scaled = self.scaler.transform(feature_vector)
        
        # Make prediction
        is_phishing = bool(self.model.predict(X_scaled)[0])
        confidence = float(max(self.model.predict_proba(X_scaled)[0]))
        
        return is_phishing, confidence, feature_dict

# Create an instance of the predictor
predictor = PhishingURLPredictor()

# Initialize with some basic training data if not already trained
if not predictor.is_trained:
    # Simple initial training set with obvious examples
    urls = [
        'https://www.google.com',
        'https://www.amazon.com',
        'https://facebook.com',
        'http://apple.com',
        'http://applle-verification.com/login',
        'http://secure-paypal.com.verify.info/login.php',
        'http://banking.secure-wells-fargo.com.logon.update',
        'http://192.168.1.1/admin/login.php',
        'http://verify-account-update-information.com'
    ]
    # Simple labels: 0 = legitimate, 1 = phishing
    labels = [0, 0, 0, 0, 1, 1, 1, 1, 1]
    
    try:
        predictor.train_model(urls, labels)
        logging.info("Initialized ML model with basic training data")
    except Exception as e:
        logging.error(f"Error training initial model: {e}")

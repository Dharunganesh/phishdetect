import logging
from flask import request, jsonify
from ml_model import predictor
from virustotal_api import VirusTotalAPI
from models import PhishingURL, db
from sqlalchemy import text
import urllib.parse
import os
from datetime import datetime, timedelta

# Initialize VirusTotal API
vt_api = VirusTotalAPI()

# Constants for phishing detection
PHISHING_CONFIDENCE_THRESHOLD = 0.85  # Increased from default to reduce false positives
VIRUSTOTAL_WEIGHT = 0.4  # Increased weight for VirusTotal results
ML_WEIGHT = 0.6  # Decreased weight for ML model results

def register_routes(app):
    """Register API routes with the Flask app"""
    
    @app.route('/api/check_url', methods=['POST'])
    def check_url():
        """API endpoint to check if a URL is a phishing attempt"""
        try:
            data = request.get_json()
            if not data or 'url' not in data:
                return jsonify({
                    'error': 'URL is required',
                    'status': 'error'
                }), 400

            url = data['url']
            logger.info(f"Checking URL: {url}")

            # Check if URL exists in database
            existing_url = PhishingURL.query.filter_by(url=url).first()
            if existing_url:
                logger.info(f"URL found in database: {url}")
                return jsonify({
                    'url': url,
                    'is_phishing': existing_url.is_phishing,
                    'confidence': existing_url.confidence,
                    'virustotal_score': existing_url.virustotal_score,
                    'last_checked': existing_url.last_checked.isoformat(),
                    'source': 'database'
                })

            # Get ML model prediction
            ml_confidence = get_ml_prediction(url)
            logger.info(f"ML confidence for {url}: {ml_confidence}")

            # Get VirusTotal score if configured
            vt_score = 0
            if os.environ.get('VIRUSTOTAL_API_KEY'):
                vt_score = get_virustotal_score(url)
                logger.info(f"VirusTotal score for {url}: {vt_score}")

            # Calculate final confidence
            final_confidence = calculate_confidence(ml_confidence, vt_score)
            is_phishing = final_confidence >= PHISHING_CONFIDENCE_THRESHOLD

            # Store result in database
            new_url = PhishingURL(
                url=url,
                is_phishing=is_phishing,
                confidence=final_confidence,
                virustotal_score=vt_score,
                last_checked=datetime.utcnow()
            )
            db.session.add(new_url)
            db.session.commit()

            return jsonify({
                'url': url,
                'is_phishing': is_phishing,
                'confidence': final_confidence,
                'ml_confidence': ml_confidence,
                'virustotal_score': vt_score,
                'last_checked': new_url.last_checked.isoformat(),
                'source': 'new_check'
            })

        except Exception as e:
            logger.error(f"Error checking URL: {str(e)}")
            return jsonify({
                'error': 'Failed to check URL',
                'details': str(e),
                'status': 'error'
            }), 500
    
    @app.route('/api/recent_phishing', methods=['GET'])
    def recent_phishing():
        """API endpoint to get recent phishing URLs"""
        try:
            # Get phishing URLs from the last 24 hours
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            recent_urls = PhishingURL.query.filter(
                PhishingURL.is_phishing == True,
                PhishingURL.last_checked >= cutoff_time
            ).order_by(PhishingURL.last_checked.desc()).limit(10).all()

            return jsonify({
                'urls': [{
                    'url': url.url,
                    'confidence': url.confidence,
                    'virustotal_score': url.virustotal_score,
                    'last_checked': url.last_checked.isoformat()
                } for url in recent_urls]
            })
            
        except Exception as e:
            logger.error(f"Error getting recent phishing URLs: {str(e)}")
            return jsonify({
                'error': 'Failed to get recent phishing URLs',
                'details': str(e),
                'status': 'error'
            }), 500
    
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        try:
            # Check database connection
            db.session.execute(text('SELECT 1'))
            database_connected = True
        except Exception as e:
            logger.error(f"Database health check failed: {str(e)}")
            database_connected = False

        # Check ML model
        try:
            # Simple test prediction
            test_url = "https://example.com"
            ml_confidence = get_ml_prediction(test_url)
            ml_model_trained = ml_confidence is not None
        except Exception as e:
            logger.error(f"ML model health check failed: {str(e)}")
            ml_model_trained = False

        return jsonify({
            'status': 'up' if database_connected else 'degraded',
            'database_connected': database_connected,
            'ml_model_trained': ml_model_trained,
            'virustotal_configured': bool(os.environ.get('VIRUSTOTAL_API_KEY'))
        })

def get_ml_prediction(url):
    """
    Get ML model prediction for a URL
    Returns confidence score between 0 and 1
    """
    try:
        # TODO: Implement actual ML model prediction
        # For now, return a dummy confidence score
        return 0.5
    except Exception as e:
        logger.error(f"ML prediction error: {str(e)}")
        return 0.0

def get_virustotal_score(url):
    """
    Get VirusTotal score for a URL
    Returns score between 0 and 1
    """
    try:
        api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        if not api_key:
            return 0.0

        # TODO: Implement actual VirusTotal API call
        # For now, return a dummy score
        return 0.0
    except Exception as e:
        logger.error(f"VirusTotal API error: {str(e)}")
        return 0.0

def calculate_confidence(ml_confidence, vt_score):
    """
    Calculate final confidence score using weighted average
    """
    return (ml_confidence * ML_WEIGHT) + (vt_score * VIRUSTOTAL_WEIGHT)

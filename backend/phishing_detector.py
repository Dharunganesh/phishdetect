import logging
from flask import request, jsonify
from ml_model import predictor
from virustotal_api import VirusTotalAPI
from models import PhishingURL, db
from sqlalchemy import text
import urllib.parse
import os

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
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'Missing URL parameter',
                'status': 'error'
            }), 400
        
        url = data['url']
        
        # Validate URL format
        try:
            result = urllib.parse.urlparse(url)
            if not all([result.scheme, result.netloc]):
                return jsonify({
                    'error': 'Invalid URL format',
                    'status': 'error'
                }), 400
        except Exception as e:
            logging.error(f"URL parsing error: {e}")
            return jsonify({
                'error': 'Invalid URL format',
                'status': 'error'
            }), 400
            
        # Check if this is a user report
        is_user_report = data.get('report', False)
        user_classification = data.get('is_phishing', None)
        
        # Check if URL is already in database
        existing_url = PhishingURL.query.filter_by(url=url).first()
        if existing_url and not is_user_report:
            logging.info(f"URL {url} found in database")
            return jsonify({
                'url': url,
                'is_phishing': existing_url.is_phishing,
                'confidence': existing_url.ml_confidence,
                'virustotal_positives': existing_url.virustotal_positives,
                'virustotal_total': existing_url.virustotal_total,
                'source': 'database',
                'status': 'success'
            })
        elif existing_url and is_user_report and user_classification is not None:
            # Update existing URL with user report
            existing_url.is_phishing = user_classification
            # If user reports as phishing, increase confidence
            if user_classification:
                existing_url.ml_confidence = max(0.95, existing_url.ml_confidence)
            db.session.commit()
            logging.info(f"Updated URL {url} in database with user report")
            return jsonify({
                'url': url,
                'is_phishing': existing_url.is_phishing,
                'confidence': existing_url.ml_confidence,
                'virustotal_positives': existing_url.virustotal_positives,
                'virustotal_total': existing_url.virustotal_total,
                'source': 'user_report',
                'status': 'success'
            })
        
        # For user reports, we trust the user's classification
        if is_user_report and user_classification is not None:
            is_phishing = user_classification
            confidence = 0.95 if user_classification else 0.05
            features = {}
        else:
            # Use ML model to check URL
            is_phishing, confidence, features = predictor.predict(url)
            
            # Apply stricter threshold for phishing classification
            if confidence < PHISHING_CONFIDENCE_THRESHOLD:
                is_phishing = False
                logging.info(f"URL {url} confidence {confidence} below threshold {PHISHING_CONFIDENCE_THRESHOLD}, marking as safe")
        
        # For demo purposes: Make VirusTotal API optional with a timeout
        # If it takes too long, we'll continue with just the ML model result
        vt_result = None
        try:
            import threading
            import queue
            
            # Run VirusTotal check in a thread with a timeout
            q = queue.Queue()
            def vt_check():
                try:
                    q.put(vt_api.check_url(url))
                except:
                    q.put(None)
            
            vt_thread = threading.Thread(target=vt_check)
            vt_thread.daemon = True
            vt_thread.start()
            vt_thread.join(8)  # Wait max 8 seconds
            
            if not q.empty():
                vt_result = q.get()
        except Exception as e:
            logging.error(f"Error with threaded VirusTotal check: {e}")
            
        vt_positives = None
        vt_total = None
        
        if vt_result:
            vt_positives = vt_result.get('malicious', 0) + vt_result.get('suspicious', 0)
            vt_total = vt_result.get('total', 0)
            
            # Adjust confidence based on VirusTotal results if available
            if vt_total > 0:
                vt_confidence = vt_positives / vt_total
                # Weighted average between ML and VirusTotal with adjusted weights
                confidence = (confidence * ML_WEIGHT) + (vt_confidence * VIRUSTOTAL_WEIGHT)
                
                # More conservative classification rules
                if vt_confidence > 0.6 and not is_phishing:  # Increased threshold
                    is_phishing = True
                    confidence = max(confidence, 0.85)  # Ensure high confidence for VirusTotal positives
                elif vt_confidence < 0.2 and is_phishing:  # Increased threshold
                    is_phishing = False
                    confidence = min(confidence, 0.15)  # Ensure low confidence for VirusTotal negatives
                
                logging.info(f"URL {url} final confidence: {confidence}, is_phishing: {is_phishing}")
        
        # Store the result in database
        try:
            new_url = PhishingURL(
                url=url,
                is_phishing=is_phishing,
                ml_confidence=confidence,
                virustotal_positives=vt_positives,
                virustotal_total=vt_total,
                features=features
            )
            db.session.add(new_url)
            db.session.commit()
            logging.info(f"Stored URL {url} in database")
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error storing URL in database: {e}")
        
        # Return the result
        source = 'user_report' if is_user_report else 'analysis'
        return jsonify({
            'url': url,
            'is_phishing': is_phishing,
            'confidence': confidence,
            'virustotal_positives': vt_positives,
            'virustotal_total': vt_total,
            'source': source,
            'status': 'success'
        })
    
    @app.route('/api/recent_phishing', methods=['GET'])
    def recent_phishing():
        """API endpoint to get recent phishing URLs"""
        try:
            limit = request.args.get('limit', 10, type=int)
            offset = request.args.get('offset', 0, type=int)
            
            # Limit to reasonable values
            if limit > 100:
                limit = 100
                
            # Query database for recent phishing URLs
            urls = PhishingURL.query.filter_by(is_phishing=True) \
                                   .order_by(PhishingURL.created_at.desc()) \
                                   .limit(limit).offset(offset).all()
            
            return jsonify({
                'urls': [url.to_dict() for url in urls],
                'count': len(urls),
                'status': 'success'
            })
            
        except Exception as e:
            logging.error(f"Error retrieving recent phishing URLs: {e}")
            return jsonify({
                'error': str(e),
                'status': 'error'
            }), 500
    
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        try:
            health_status = {
                'status': 'up',
                'ml_model_trained': predictor.is_trained,
                'database_connected': False,
                'virustotal_configured': bool(os.environ.get("VIRUSTOTAL_API_KEY"))
            }
            
            # Check database connection
            try:
                db.session.execute(text('SELECT 1'))
                health_status['database_connected'] = True
            except Exception as e:
                logging.error(f"Database health check failed: {e}")
                health_status['status'] = 'degraded'
                health_status['database_error'] = str(e)
            
            # If database is not connected, return error status
            if not health_status['database_connected']:
                response = jsonify(health_status)
                response.headers.add('Access-Control-Allow-Origin', '*')
                response.headers.add('Access-Control-Allow-Methods', 'GET')
                response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
                return response, 503
                
            response = jsonify(health_status)
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Methods', 'GET')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
            return response
        except Exception as e:
            logging.error(f"Health check failed: {e}")
            error_response = jsonify({
                'status': 'error',
                'error': str(e)
            })
            error_response.headers.add('Access-Control-Allow-Origin', '*')
            error_response.headers.add('Access-Control-Allow-Methods', 'GET')
            error_response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
            return error_response, 500

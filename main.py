import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.abspath('backend'))

# Import the Flask app from backend
try:
    from backend.app import app
except ImportError:
    try:
        from app import app
    except ImportError:
        # If both imports fail, create a simple app for testing
        from flask import Flask
        app = Flask(__name__)
        
        @app.route('/')
        def home():
            return 'PhishGuard API Server'
            
        @app.route('/api/health')
        def health():
            return {'status': 'up'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
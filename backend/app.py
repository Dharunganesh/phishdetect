import os
import logging
import sys

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_cors import CORS

# Set up logging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s [%(levelname)s] %(message)s',
                   handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "phishing_detector_secret")

# Enable CORS for the Chrome extension
CORS(app)

# Apply middleware for HTTPS support
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database connection to NeonDB
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    logger.error("DATABASE_URL environment variable is not set! Application will fail to start.")
    print("ERROR: DATABASE_URL environment variable is not set!")
    # Don't exit here to allow Railway's health checks to pass in some cases

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Check for VirusTotal API key
if not os.environ.get("VIRUSTOTAL_API_KEY"):
    logger.warning("VIRUSTOTAL_API_KEY environment variable is not set! VirusTotal integration will be disabled.")
    print("WARNING: VIRUSTOTAL_API_KEY environment variable is not set!")

# Initialize the app with SQLAlchemy
db.init_app(app)

# Basic route for the home page
@app.route('/')
def home():
    """Home page route - simple status page"""
    return '''
    <html>
        <head>
            <title>PhishDetect API</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; color: #333; }
                h1 { color: #2c3e50; }
                .container { max-width: 800px; margin: 0 auto; }
                .status { padding: 15px; background-color: #dff0d8; border: 1px solid #d6e9c6; border-radius: 4px; color: #3c763d; }
                .endpoints { margin-top: 20px; }
                .endpoint { background-color: #f5f5f5; padding: 10px; margin-bottom: 10px; border-radius: 4px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>PhishDetect API Server</h1>
                <div class="status">
                    <strong>Status:</strong> Running
                </div>
                <div class="endpoints">
                    <h2>Available Endpoints:</h2>
                    <div class="endpoint"><strong>GET /api/health</strong> - Health check endpoint</div>
                    <div class="endpoint"><strong>POST /api/check_url</strong> - Check if a URL is a phishing attempt</div>
                    <div class="endpoint"><strong>GET /api/recent_phishing</strong> - Get recently detected phishing URLs</div>
                </div>
            </div>
        </body>
    </html>
    '''

# Import routes after db initialization to avoid circular imports
from phishing_detector import register_routes

# Initialize database tables and register API routes
with app.app_context():
    # Import models so they're registered with SQLAlchemy
    import models
    
    # Create all tables
    db.create_all()
    
    # Register API routes
    register_routes(app)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

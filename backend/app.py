import os
import logging
import sys
from flask import Flask, request, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_cors import CORS
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text
import psycopg2
from urllib.parse import urlparse
from extensions import db
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s [%(levelname)s] %(message)s',
                   handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)

def test_db_connection(db_url):
    """Test database connection and return connection details"""
    try:
        # Parse the database URL
        parsed = urlparse(db_url)
        logger.info(f"Testing connection to database at {parsed.hostname}:{parsed.port}")
        
        # Try to connect
        conn = psycopg2.connect(db_url)
        cursor = conn.cursor()
        cursor.execute('SELECT version();')
        version = cursor.fetchone()
        cursor.close()
        conn.close()
        
        logger.info(f"Successfully connected to database. Version: {version[0]}")
        return True
    except Exception as e:
        logger.error(f"Database connection test failed: {str(e)}")
        return False

# Debug environment variables
logger.info("Checking environment variables...")
logger.info(f"All environment variables: {dict(os.environ)}")

# Try to find database URL in different possible locations
database_url = None
possible_db_vars = [
    'DATABASE_URL',
    'RAILWAY_DATABASE_URL',
    'POSTGRES_URL',
    'POSTGRESQL_URL',
    'PGDATABASE_URL'
]

for var in possible_db_vars:
    if var in os.environ:
        database_url = os.environ[var]
        logger.info(f"Found database URL in {var}")
        break

if not database_url:
    # Try to construct from individual components
    db_components = {
        'user': os.environ.get('PGUSER', 'postgres'),
        'password': os.environ.get('PGPASSWORD'),
        'host': os.environ.get('PGHOST'),
        'port': os.environ.get('PGPORT', '5432'),
        'database': os.environ.get('PGDATABASE', 'railway')
    }
    
    logger.info(f"Database components found: {db_components}")
    
    # Check if we have the minimum required components
    if db_components['host'] and db_components['password']:
        database_url = f"postgresql://{db_components['user']}:{db_components['password']}@{db_components['host']}:{db_components['port']}/{db_components['database']}"
        logger.info("Constructed DATABASE_URL from individual components")
    else:
        # Try to get the database URL from Railway's internal DNS
        if 'RAILWAY_PRIVATE_DOMAIN' in os.environ:
            host = os.environ['RAILWAY_PRIVATE_DOMAIN'].replace('web.', 'postgres.')
            database_url = f"postgresql://postgres:postgres@{host}:5432/railway"
            logger.info("Constructed DATABASE_URL from Railway private domain")
        else:
            logger.error("No database URL found in any environment variables")
            logger.error("Please ensure you have a PostgreSQL database service linked to your application")
            sys.exit(1)

# If the URL starts with postgres://, change it to postgresql://
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
    logger.info("Updated database URL protocol from postgres:// to postgresql://")

# Test the database connection
if not test_db_connection(database_url):
    logger.error("Failed to connect to database. Please check your database configuration.")
    sys.exit(1)

# Log database configuration (masked for security)
masked_url = database_url[:10] + '...' + database_url[-10:] if len(database_url) > 20 else '***'
logger.info(f"Using database URL: {masked_url}")

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "phishing_detector_secret")

# Enable CORS for the Chrome extension with proper method handling
CORS(app, resources={
    r"/*": {  # Allow CORS for all routes
        "origins": ["chrome-extension://*", "http://localhost:*", "http://127.0.0.1:*", "https://*"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "Accept", "Origin", "X-Requested-With"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# Apply middleware for HTTPS support
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Add OPTIONS method handler for all routes
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept,Origin,X-Requested-With')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
    "pool_size": 5,
    "max_overflow": 10,
    "pool_timeout": 30
}

# Check for VirusTotal API key
if not os.environ.get("VIRUSTOTAL_API_KEY"):
    logger.warning("VIRUSTOTAL_API_KEY environment variable is not set! VirusTotal integration will be disabled.")
    print("WARNING: VIRUSTOTAL_API_KEY environment variable is not set!")

# Initialize the app with SQLAlchemy
db.init_app(app)

# Error handlers
@app.errorhandler(SQLAlchemyError)
def handle_db_error(error):
    logger.error(f"Database error: {error}")
    return jsonify({
        'error': 'Database error occurred',
        'status': 'error'
    }), 503

@app.errorhandler(Exception)
def handle_generic_error(error):
    logger.error(f"Unexpected error: {error}")
    return jsonify({
        'error': 'An unexpected error occurred',
        'status': 'error'
    }), 500

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
    try:
        # Import models so they're registered with SQLAlchemy
        import models
        
        # Create all tables
        db.create_all()
        
        # Test database connection using SQLAlchemy
        try:
            db.session.execute(text('SELECT 1'))
            logger.info("Database connection test successful using SQLAlchemy")
        except Exception as e:
            logger.error(f"Database connection test failed using SQLAlchemy: {e}")
            sys.exit(1)
        
        # Register API routes
        register_routes(app)
        
        # Log all registered routes
        logger.info("Registered routes:")
        for rule in app.url_map.iter_rules():
            logger.info(f"Route: {rule.rule} - Methods: {rule.methods}")
        
        logger.info("Application initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

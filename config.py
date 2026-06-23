import os

class Config:
    # Security Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'soc-sentinel-xdr-super-secret-key-2026')
    
    # Database Configuration (PostgreSQL ready with SQLite fallback)
    db_url = os.environ.get('DATABASE_URL', 'sqlite:///soc_sentinel.db')
    
    # Convert Render-provided postgres:// to postgresql:// for SQLAlchemy compatibility
    if db_url and db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
        
    SQLALCHEMY_DATABASE_URI = db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Directory paths
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    
    # Upload configurations (supports persistent disk mount paths in production)
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', os.path.join(BASE_DIR, 'uploads'))
    ALLOWED_EXTENSIONS = {'txt', 'csv', 'log'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max limit
    
    # GeoLite2 Path
    GEOLITE2_DB_PATH = os.environ.get('GEOLITE2_DB_PATH', os.path.join(BASE_DIR, 'GeoLite2-City.mmdb'))

import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'soc-sentinel-xdr-super-secret-key-2026')
    
    # Database
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'soc_sentinel.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Upload limits
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    ALLOWED_EXTENSIONS = {'txt', 'csv', 'log'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max limit
    
    # GeoLite2 Path
    # Can be placed in the project directory for custom lookups
    GEOLITE2_DB_PATH = os.environ.get('GEOLITE2_DB_PATH', os.path.join(BASE_DIR, 'GeoLite2-City.mmdb'))

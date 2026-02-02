import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database Configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', 'sumo@123'),
    'database': os.getenv('DB_NAME', 'rajya_sabha'),
    'ssl_disabled': False,
    'connect_timeout': 30
}

# API Configuration
API_KEY = os.getenv('API_KEY', '321')

# App Configuration
APP_NAME = "Rajya Sabha Members API"
APP_VERSION = "1.0.0"
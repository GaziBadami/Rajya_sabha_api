import mysql.connector
from mysql.connector import Error
from config import DB_CONFIG
import logging

logger = logging.getLogger(__name__)

def get_database_connection():
    """Creates and returns a database connection"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except Error as e:
        logger.error(f"Database connection error: {e}")
        return None

def close_connection(connection):
    """Closes the database connection properly"""
    if connection and connection.is_connected():
        connection.close()
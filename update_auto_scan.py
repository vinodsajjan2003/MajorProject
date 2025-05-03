"""
Database migration script to add AutoScanURL table and update Scan table.
"""
import os
import logging
from app import app, db
from sqlalchemy import text, inspect
from models import AutoScanURL, Scan

def add_column_if_not_exists(table_name, column_name, column_type):
    """Add a column to a table if it doesn't exist"""
    inspector = inspect(db.engine)
    columns = [column['name'] for column in inspector.get_columns(table_name)]
    
    if column_name not in columns:
        logging.info(f"Adding column {column_name} to {table_name}")
        sql = text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
        db.session.execute(sql)
        db.session.commit()
        return True
    return False

def update_database():
    """Update the database with new tables and columns"""
    with app.app_context():
        # Create new tables
        db.create_all()
        
        # Add auto_scan_url_id column to Scan table if it doesn't exist
        add_column_if_not_exists('scan', 'auto_scan_url_id', 'INTEGER')
        
        logging.info("Database schema updated successfully")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    update_database()
    print("Database updated successfully.")
from app import app, db
import logging
import models  # Import models to ensure they're registered
from sqlalchemy import MetaData, Table, Column, Text, String
from sqlalchemy.sql import text

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def add_column_if_not_exists(table_name, column_name, column_type):
    """Add a column to a table if it doesn't exist"""
    try:
        query = text(f"""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = '{table_name}' AND column_name = '{column_name}'
        """)
        with db.engine.connect() as conn:
            result = conn.execute(query)
            exists = result.fetchone() is not None
            
        if not exists:
            query = text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
            with db.engine.connect() as conn:
                conn.execute(query)
                conn.commit()
            logger.info(f"Added {column_name} column to {table_name} table")
            return True
        else:
            logger.info(f"Column {column_name} already exists in {table_name} table")
            return False
    except Exception as e:
        logger.error(f"Error adding column {column_name} to {table_name} table: {str(e)}")
        return False

if __name__ == "__main__":
    with app.app_context():
        logger.info("Starting database update...")
        
        try:
            # First check if the tables exist at all
            inspector = db.inspect(db.engine)
            if 'scan' not in inspector.get_table_names():
                logger.info("Scan table doesn't exist yet. Creating all tables...")
                db.create_all()
                logger.info("All tables created successfully!")
            else:
                logger.info("Scan table exists, adding new columns if needed...")
                
                # Add columns to scan table
                add_column_if_not_exists('scan', 'description', 'TEXT')
                add_column_if_not_exists('scan', 'ioc', 'VARCHAR(255)')
                add_column_if_not_exists('scan', 'source', 'VARCHAR(128)')
            
            logger.info("Database update completed successfully!")
        except Exception as e:
            logger.error(f"Error updating database: {str(e)}")
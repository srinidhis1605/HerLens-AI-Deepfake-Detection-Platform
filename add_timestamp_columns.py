# add_timestamp_columns.py
"""
Run this script ONCE to add the timestamp columns to your existing database
This will NOT delete any of your data
"""

from app import app, db
from sqlalchemy import inspect, text
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def add_column_if_not_exists(column_name, column_type):
    """Add a column to the analysis table if it doesn't exist"""
    inspector = inspect(db.engine)
    
    # Get existing columns
    columns = [col['name'] for col in inspector.get_columns('analysis')]
    
    if column_name not in columns:
        logger.info(f"➕ Adding column: {column_name}")
        try:
            with db.engine.connect() as conn:
                conn.execute(text(f"ALTER TABLE analysis ADD COLUMN {column_name} {column_type}"))
                conn.commit()
            logger.info(f"✅ Successfully added {column_name}")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to add {column_name}: {e}")
            return False
    else:
        logger.info(f"✓ Column {column_name} already exists")
        return True

def run_migration():
    """Run the database migration"""
    logger.info("="*50)
    logger.info("🔄 Starting database migration...")
    logger.info("="*50)
    
    with app.app_context():
        # Add all three new columns
        add_column_if_not_exists('crypto_timestamp', 'VARCHAR(500)')
        add_column_if_not_exists('timestamp_hash', 'VARCHAR(64)')
        add_column_if_not_exists('timestamp_signature', 'VARCHAR(200)')
    
    logger.info("="*50)
    logger.info("🎉 Migration complete! Your existing data is preserved.")
    logger.info("="*50)

if __name__ == "__main__":
    run_migration()
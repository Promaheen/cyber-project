import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'security_events.db')

def clear_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("Clearing all event logs...")
    cursor.execute('DELETE FROM events')
    conn.commit()
    
    conn.close()
    print("Database cleared. Dashboard should be empty now.")

if __name__ == "__main__":
    clear_db()

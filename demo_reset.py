import sqlite3
import datetime
from datetime import timedelta, timezone

def utc_now():
    return datetime.datetime.now(timezone.utc)

def close_active_incidents():
    # Connect to the DB
    conn = sqlite3.connect("./data/honeykey.db")
    
    # We want to force the next event to create a NEW incident.
    # The logic looks for an incident where last_seen >= (now - 30 mins)
    # So if we update 'last_seen' to be 31 mins ago, the logic will fail to find it
    # and create a new incident.
    
    old_time = (utc_now() - timedelta(minutes=60)).isoformat()
    
    print("Force-closing active incidents (setting last_seen to 60 mins ago)...")
    
    cursor = conn.execute(
        "UPDATE incidents SET last_seen = ? WHERE last_seen > ?",
        (old_time, old_time)
    )
    
    print(f"Closed {cursor.rowcount} active incidents.")
    conn.commit()
    conn.close()

if __name__ == "__main__":
    close_active_incidents()

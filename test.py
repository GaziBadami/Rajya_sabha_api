from database import get_database_connection, close_connection

# Try to connect
conn = get_database_connection()

if conn:
    print("✅ Database connected successfully!")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM members")
    count = cursor.fetchone()[0]
    print(f"✅ Found {count} IPOs in database")
    cursor.close()
    close_connection(conn)
else:
    print("❌ Connection failed!")
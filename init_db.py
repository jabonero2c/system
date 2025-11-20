import sqlite3


def init_db(db_connection):
    """
    Initializes the database schema by creating all necessary tables.
    This function is called automatically by app.py if 'blood.db' does not exist.
    """
    try:
        cursor = db_connection.cursor()

        # 1. Users Table (Core information)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                role TEXT CHECK(role IN ('donor', 'requester', 'admin')) NOT NULL,
                blood_type TEXT NOT NULL,
                location TEXT NOT NULL,
                points INTEGER DEFAULT 0
            );
        """)

        # 2. Requests Table (Blood requests from users)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requester_id INTEGER NOT NULL,
                blood_type_needed TEXT NOT NULL,
                location_needed TEXT NOT NULL,
                contact_info TEXT,
                details_text TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT CHECK(status IN ('Pending', 'Fulfilled', 'Cancelled')) NOT NULL DEFAULT 'Pending',
                FOREIGN KEY (requester_id) REFERENCES users (id)
            );
        """)

        # 3. Posts Table (Educational content or general announcements)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                author_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (author_id) REFERENCES users (id)
            );
        """)

        # 4. Transactions Table (Tracking donations/points exchange)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                donor_id INTEGER NOT NULL,
                request_id INTEGER,
                amount_of_blood_ml INTEGER NOT NULL,
                points_awarded INTEGER NOT NULL,
                transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (donor_id) REFERENCES users (id),
                FOREIGN KEY (request_id) REFERENCES requests (id)
            );
        """)

        # 5. Reviews Table (Feedback system)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reviewer_id INTEGER NOT NULL,
                reviewed_user_id INTEGER NOT NULL,
                rating INTEGER CHECK(rating >= 1 AND rating <= 5) NOT NULL,
                comment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (reviewer_id) REFERENCES users (id),
                FOREIGN KEY (reviewed_user_id) REFERENCES users (id)
            );
        """)

        db_connection.commit()
        print("All tables created successfully.")
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")


if __name__ == '__main__':
    # Simple test case for the script (creates 'test_blood.db')
    conn = sqlite3.connect('test_blood.db')
    init_db(conn)
    conn.close()
    print("Test database 'test_blood.db' created.")
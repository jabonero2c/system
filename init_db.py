import sqlite3
from datetime import datetime
import os

# --- Configuration ---
DATABASE = 'instance/savebloodon.db'

def init_db():
    # Ensure the instance directory exists
    if not os.path.exists('instance'):
        os.makedirs('instance')

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Drop tables if they exist for clean slate
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("DROP TABLE IF EXISTS requests")
    cursor.execute("DROP TABLE IF EXISTS transactions")
    cursor.execute("DROP TABLE IF EXISTS posts")
    cursor.execute("DROP TABLE IF EXISTS blood_banks")

    # --- 1. Users Table ---
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            blood_type TEXT NOT NULL,
            location TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('donor', 'recipient', 'admin'))
        )
    """)

    # Mock Users
    users_data = [
        ('admin', 'password', 'AB+', 'Central City', 'admin'),
        ('DonorCebu', 'password', 'O+', 'Lahug, Cebu City', 'donor'),
        ('DonorMandaue', 'password', 'A-', 'Mandaue City', 'donor'),
        ('RecipientA', 'password', 'B+', 'Central City', 'recipient'),
        ('RecipientB', 'password', 'O-', 'Mandaue City', 'recipient')
    ]
    cursor.executemany("INSERT INTO users (username, password, blood_type, location, role) VALUES (?, ?, ?, ?, ?)", users_data)

    # Get user IDs for foreign keys
    admin_id = cursor.execute("SELECT id FROM users WHERE username='admin'").fetchone()[0]
    donor_cebu_id = cursor.execute("SELECT id FROM users WHERE username='DonorCebu'").fetchone()[0]
    recipient_a_id = cursor.execute("SELECT id FROM users WHERE username='RecipientA'").fetchone()[0]

    # --- 2. Blood Banks Table ---
    cursor.execute("""
        CREATE TABLE blood_banks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            location TEXT NOT NULL
        )
    """)
    banks_data = [
        ('Cebu Red Cross', 'Cebu City'),
        ('Mandaue Health Center', 'Mandaue City')
    ]
    cursor.executemany("INSERT INTO blood_banks (name, location) VALUES (?, ?)", banks_data)

    bank_cebu_id = cursor.execute("SELECT id FROM blood_banks WHERE name='Cebu Red Cross'").fetchone()[0]

    # --- 3. Requests Table (Public Requests) ---
    cursor.execute("""
        CREATE TABLE requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER NOT NULL,
            blood_type_needed TEXT NOT NULL,
            location_needed TEXT NOT NULL,
            contact_info TEXT,
            details TEXT,
            status TEXT NOT NULL CHECK (status IN ('Pending', 'Approved', 'Declined', 'Completed', 'Cancelled')),
            FOREIGN KEY (requester_id) REFERENCES users (id)
        )
    """)
    requests_data = [
        # Approved request for DonorCebu to see
        (recipient_a_id, 'O+', 'Lahug, Cebu City', '0917-1234567', 'Urgent need after accident.', 'Approved'),
        # Pending request for Admin to review
        (recipient_a_id, 'AB-', 'Central City Hospital', '0917-0001111', 'Scheduled surgery next week.', 'Pending')
    ]
    cursor.executemany("INSERT INTO requests (requester_id, blood_type_needed, location_needed, contact_info, details, status) VALUES (?, ?, ?, ?, ?, ?)", requests_data)

    # --- 4. Transactions Table (Direct Recipient-Donor Messages) ---
    cursor.execute("""
        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER NOT NULL,
            donor_id INTEGER NOT NULL,
            blood_type_needed TEXT NOT NULL,
            location_needed TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('Pending', 'Completed', 'Cancelled')),
            FOREIGN KEY (requester_id) REFERENCES users (id),
            FOREIGN KEY (donor_id) REFERENCES users (id)
        )
    """)
    # Mock transaction for DonorCebu to see in their dashboard
    cursor.execute(
        "INSERT INTO transactions (requester_id, donor_id, blood_type_needed, location_needed, message, timestamp, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (recipient_a_id, donor_cebu_id, 'O+', 'Cebu Doctors', 'Can you please donate O+? It is extremely urgent.', datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'Pending')
    )

    # --- 5. Posts Table (Donor Success Stories) ---
    cursor.execute("""
        CREATE TABLE posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            blood_bank_id INTEGER,
            timestamp DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (blood_bank_id) REFERENCES blood_banks (id)
        )
    """)
    # Mock post for Recipient to see
    cursor.execute(
        "INSERT INTO posts (user_id, content, blood_bank_id, timestamp) VALUES (?, ?, ?, ?)",
        (donor_cebu_id, "Just finished my O+ donation! Feeling great and ready to help again soon.", bank_cebu_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    )

    conn.commit()
    conn.close()
    print(f"Database '{DATABASE}' initialized with mock data successfully.")

if __name__ == '__main__':
    init_db()
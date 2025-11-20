import sqlite3 # FIX: Added missing import
import secrets
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)

# Ensure the instance directory exists
if not os.path.exists('instance'):
    os.makedirs('instance')

DATABASE = 'instance/test_blood.db'


# --- SECURITY HELPERS ---

def hash_password(password):
    """Hashes a password using SHA-256 for basic security."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def check_password(hashed_password, provided_password):
    """Checks a provided plain password against a hashed one."""
    return hashed_password == hash_password(provided_password)


# -----------------------------------------------------------

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        # FIX: sqlite3 is now imported and accessible
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    """Helper function to query the database."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def execute_db(query, args=()):
    """Helper function to execute changes (INSERT, UPDATE, DELETE)."""
    db = get_db()
    db.execute(query, args)
    db.commit()


def add_mock_blood_bank():
    """Inserts a mock blood bank if none exist."""
    # Use execute to get a simple count without relying on the row_factory key name
    db = get_db()
    cursor = db.cursor()
    count_row = cursor.execute('SELECT COUNT(*) FROM blood_banks').fetchone()
    count = count_row[0] if count_row else 0

    if count == 0:
        print("Inserting mock blood banks...")
        execute_db(
            "INSERT INTO blood_banks (name, location) VALUES (?, ?)",
            ('Philippine Red Cross - Cebu Chapter', 'Cebu City')
        )
        execute_db(
            "INSERT INTO blood_banks (name, location) VALUES (?, ?)",
            ('Perpetual Succour Hospital Blood Bank', 'Lahug, Cebu')
        )
        execute_db(
            "INSERT INTO blood_banks (name, location) VALUES (?, ?)",
            ('Cebu Doctors\' University Hospital', 'Cebu City')
        )
        execute_db(
            "INSERT INTO blood_banks (name, location) VALUES (?, ?)",
            ('Chong Hua Hospital Blood Center', 'Cebu City')
        )
        execute_db(
            "INSERT INTO blood_banks (name, location) VALUES (?, ?)",
            ('Vicente Sotto Memorial Medical Center', 'Cebu City')
        )


# --- Automatic Database Initialization ---

def init_db_on_startup():
    """
    Creates tables if they do not exist and inserts initial mock data.
    """
    db = get_db()
    cursor = db.cursor()

    # Create Tables (using IF NOT EXISTS to prevent dropping existing data)

    # FIX: Changed 'password' column to 'password_hash' for security
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            blood_type TEXT NOT NULL,
            location TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('donor', 'recipient', 'admin'))
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blood_banks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            location TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER NOT NULL,
            donor_id INTEGER,
            blood_type_needed TEXT NOT NULL,
            location_needed TEXT NOT NULL,
            contact_info TEXT,
            details TEXT,
            status TEXT NOT NULL CHECK (status IN ('Pending', 'Approved', 'Declined', 'Matched', 'Completed', 'Cancelled')),
            FOREIGN KEY (requester_id) REFERENCES users (id),
            FOREIGN KEY (donor_id) REFERENCES users (id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
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

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            blood_bank_id INTEGER,
            timestamp DATETIME NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (blood_bank_id) REFERENCES blood_banks (id)
        )
    """)

    db.commit()

    # Add blood banks before checking users
    add_mock_blood_bank()

    # Insert Mock Data (Only if NO users exist)
    user_count_result = cursor.execute("SELECT COUNT(*) FROM users").fetchone()
    user_count = user_count_result[0] if user_count_result else 0

    if user_count == 0:
        print("Inserting initial mock data...")

        # Hash passwords for mock data insertion
        users_data = [
            ('admin', hash_password('password'), 'AB+', 'Central City', 'admin'),
            ('DonorO_Plus', hash_password('password'), 'O+', 'Lahug, Cebu City', 'donor'),
            ('DonorA_Minus', hash_password('password'), 'A-', 'Mandaue City', 'donor'),
            ('RecipientB_Plus', hash_password('password'), 'B+', 'Central City', 'recipient'),
        ]
        # FIX: Updated column list to include password_hash
        cursor.executemany(
            "INSERT INTO users (username, password_hash, blood_type, location, role) VALUES (?, ?, ?, ?, ?)",
            users_data)

        # Get necessary IDs
        donor_o_plus_row = cursor.execute("SELECT id FROM users WHERE username='DonorO_Plus'").fetchone()
        recipient_b_plus_row = cursor.execute("SELECT id FROM users WHERE username='RecipientB_Plus'").fetchone()

        if donor_o_plus_row and recipient_b_plus_row:
            donor_o_plus_id = donor_o_plus_row[0]
            recipient_b_plus_id = recipient_b_plus_row[0]

            # Mock Requests
            cursor.execute(
                "INSERT INTO requests (requester_id, blood_type_needed, location_needed, contact_info, details, status) VALUES (?, ?, ?, ?, ?, ?)",
                (recipient_b_plus_id, 'A+', 'Central City Hospital', '0917-1234567',
                 'Need A+ for scheduled surgery.', 'Pending')
            )
            cursor.execute(
                "INSERT INTO requests (requester_id, blood_type_needed, location_needed, contact_info, details, status) VALUES (?, ?, ?, ?, ?, ?)",
                (recipient_b_plus_id, 'O-', 'Mandaue Hospital', '0917-0001111',
                 'Urgent O- need.', 'Approved')
            )

            # Mock Transaction
            cursor.execute(
                "INSERT INTO transactions (requester_id, donor_id, blood_type_needed, location_needed, message, timestamp, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (recipient_b_plus_id, donor_o_plus_id, 'O+', 'Cebu Doctors',
                 'Can you please donate O+? You were a suggested donor.',
                 datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'Pending')
            )

        db.commit()
        print("Database structure and initial data confirmed.")


# Run the initialization function
with app.app_context():
    init_db_on_startup()


# --- User/Session Management & Dashboard Rendering ---

def get_user(user_id):
    """Fetches user details by ID."""
    if user_id is None:
        return None
    return query_db('SELECT * FROM users WHERE id = ?', (user_id,), one=True)


def get_current_user():
    """Returns the current logged-in user object."""
    return get_user(session.get('user_id'))


def render_donor_dashboard(user):
    """Renders Donor Dashboard with Direct Transaction Notifications."""
    # 1. Donor Notification (Direct Requests)
    transactions = query_db(
        """
        SELECT t.*, r.username as recipient_username 
        FROM transactions t 
        JOIN users r ON t.requester_id = r.id 
        WHERE t.donor_id = ? AND t.status = 'Pending' 
        ORDER BY t.timestamp DESC
        """,
        (user['id'],)
    )

    # 2. Approved Public Requests matching donor's blood type (For Donation Offer)
    public_requests = query_db(
        "SELECT * FROM requests WHERE status = 'Approved' AND blood_type_needed = ? LIMIT 5", (user['blood_type'],)
    )

    blood_banks = query_db('SELECT * FROM blood_banks')

    return render_template('donor_dashboard.html',
                           user=user,
                           transactions=transactions,  # Donor's direct requests/notifications
                           requests=public_requests,
                           blood_banks=blood_banks)


def render_admin_dashboard(user):
    """Renders Admin Dashboard with Pending Public Request Notifications."""
    # Admin Notification (Pending Public Requests)
    pending_requests = query_db(
        """
        SELECT r.*, u.username as requester_username 
        FROM requests r 
        JOIN users u ON r.requester_id = u.id 
        WHERE r.status = 'Pending' 
        ORDER BY r.id ASC
        """
    )

    all_users = query_db('SELECT id, username, role, blood_type, location FROM users ORDER BY id ASC')

    return render_template('admin_dashboard.html',
                           user=user,
                           pending_requests=pending_requests,  # Admin's notifications
                           all_users=all_users)


# --- Authentication Routes ---

@app.route('/')
def home():
    user = get_current_user()
    if user:
        return redirect(url_for('dashboard'))
    return render_template('home.html')


@app.route('/auth')
def auth_page():
    return render_template('auth.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']  # This is the plain password

        # FIX: Query only by username
        user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)

        # FIX: Check provided password against the stored hash
        if user and check_password(user['password_hash'], password):
            session['user_id'] = user['id']
            flash(f'Logged in successfully as {user["username"]} ({user["role"]}).', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
            # Pass flag to show login form if authentication failed
            return render_template('auth.html', error='Invalid username or password.', show_login=True)
    return redirect(url_for('auth_page'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        new_username = request.form['new_username']
        new_password = request.form['new_password']
        blood_type = request.form['blood_type']
        location = request.form['location']
        role = request.form['role']

        # Check if username already exists
        existing_user = query_db('SELECT * FROM users WHERE username = ?', (new_username,), one=True)
        if existing_user:
            flash('Username already taken.', 'error')
            # Pass flag to show register form if validation failed
            return render_template('auth.html', error='Username already taken.', show_register=True)

        # FIX: Hash the password before insertion
        hashed_password = hash_password(new_password)

        # FIX: Insert into the password_hash column
        execute_db(
            'INSERT INTO users (username, password_hash, blood_type, location, role) VALUES (?, ?, ?, ?, ?)',
            (new_username, hashed_password, blood_type, location, role)
        )

        # Retrieve the newly created user to get the ID
        new_user = query_db('SELECT * FROM users WHERE username = ?', (new_username,), one=True)
        session['user_id'] = new_user['id']

        flash(f'Account created and logged in successfully as {new_user["role"]}.', 'success')
        return redirect(url_for('dashboard'))
    return redirect(url_for('auth_page'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


@app.route('/dashboard')
def dashboard():
    user = get_current_user()
    if not user:
        flash('Please log in to view your dashboard.', 'warning')
        return redirect(url_for('auth_page'))

    if user['role'] == 'donor':
        return render_donor_dashboard(user)
    elif user['role'] == 'recipient':
        # Recipients go to the search/request page
        return redirect(url_for('search_donors'))
    elif user['role'] == 'admin':
        return render_admin_dashboard(user)
    else:
        flash('Unknown user role.', 'error')
        return redirect(url_for('logout'))


# --- Donor Post Story Route ---

@app.route('/post_story', methods=['POST'])
def post_story():
    """Handles a donor submitting a donation success story."""
    user = get_current_user()
    if not user or user['role'] != 'donor':
        flash('Permission denied.', 'error')
        return redirect(url_for('dashboard'))

    content = request.form['content']
    # blood_bank_id can be None (if the default option is selected)
    blood_bank_id = request.form.get('blood_bank_id')

    # Convert empty string from select input to None for the database
    if blood_bank_id == '':
        blood_bank_id = None
    else:
        # Ensure it's converted to an integer if it's not None
        try:
            blood_bank_id = int(blood_bank_id)
        except ValueError:
            flash('Invalid blood bank selection.', 'error')
            return redirect(url_for('dashboard'))

    try:
        execute_db(
            'INSERT INTO posts (user_id, content, blood_bank_id, timestamp) VALUES (?, ?, ?, ?)',
            (user['id'], content, blood_bank_id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
        flash('Your donation success story has been posted!', 'success')
    except Exception as e:
        flash(f'Failed to post story due to an error.', 'error')
        print(f"Error posting story: {e}")

    return redirect(url_for('dashboard'))


# --- Recipient Search & Request Routes ---

@app.route('/search_donors')
def search_donors():
    user = get_current_user()
    if not user or user['role'] != 'recipient':
        flash('Permission denied.', 'error')
        return redirect(url_for('dashboard'))

    # Load recipient's existing requests and transactions for their dashboard view
    my_requests = query_db("""
        SELECT r.*, d.username as donor_username
        FROM requests r
        LEFT JOIN users d ON r.donor_id = d.id
        WHERE r.requester_id = ? 
        ORDER BY r.id DESC
    """, (user['id'],))

    my_transactions = query_db(
        'SELECT t.*, d.username as donor_username FROM transactions t JOIN users d ON t.donor_id = d.id WHERE t.requester_id = ? ORDER BY t.timestamp DESC',
        (user['id'],)
    )

    return render_template('search_donors.html',
                           user=user,
                           donors=[],
                           search_params=None,
                           my_requests=my_requests,
                           my_transactions=my_transactions)


@app.route('/search', methods=['POST'])
def search():
    user = get_current_user()
    if not user or user['role'] != 'recipient':
        flash('Permission denied.', 'error')
        return redirect(url_for('dashboard'))

    blood_type = request.form['blood_type']
    location_keyword = request.form['location'].strip()

    search_params = {
        'blood_type': blood_type,
        'location': location_keyword
    }

    # Fetches 'Suggested Donors'
    sql = """
        SELECT id, username, blood_type, location, role FROM users
        WHERE role = 'donor'
        AND blood_type = ?
        AND location LIKE ?
        AND id != ?
    """
    donors = query_db(sql, (blood_type, f'%{location_keyword}%', user['id']))

    flash(f'Found {len(donors)} suggested donor(s) matching your criteria.', 'success')

    # Load recipient's existing requests and transactions again for the template
    my_requests = query_db("""
        SELECT r.*, d.username as donor_username
        FROM requests r
        LEFT JOIN users d ON r.donor_id = d.id
        WHERE r.requester_id = ? 
        ORDER BY r.id DESC
    """, (user['id'],))

    my_transactions = query_db(
        'SELECT t.*, d.username as donor_username FROM transactions t JOIN users d ON t.donor_id = d.id WHERE t.requester_id = ? ORDER BY t.timestamp DESC',
        (user['id'],)
    )

    return render_template('search_donors.html',
                           user=user,
                           donors=donors,  # The suggested donors
                           search_params=search_params,
                           my_requests=my_requests,
                           my_transactions=my_transactions)


@app.route('/send_transaction', methods=['POST'])
def send_transaction():
    """Recipient sends a direct request (Donor Notification Trigger)."""
    user = get_current_user()
    if not user or user['role'] != 'recipient':
        flash('Permission denied.', 'error')
        return redirect(url_for('dashboard'))

    donor_id = request.form.get('donor_id', type=int)
    message = request.form['message']
    blood_type_needed = request.form['blood_type_needed']
    location_needed = request.form['location_needed']

    donor = get_user(donor_id)
    if not donor or donor['role'] != 'donor':
        flash('Invalid donor selected.', 'error')
        return redirect(url_for('search_donors'))

    execute_db(
        'INSERT INTO transactions (requester_id, donor_id, blood_type_needed, location_needed, message, timestamp, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (user['id'], donor_id, blood_type_needed, location_needed, message,
         datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'Pending')
    )

    flash(f'Contact request sent to {donor["username"]}! They will be notified in their dashboard.', 'success')
    return redirect(url_for('search_donors'))


@app.route('/submit_request', methods=['POST'])
def submit_request():
    """Recipient submits a public request (Admin Notification Trigger)."""
    user = get_current_user()
    if not user or user['role'] != 'recipient':
        flash('Permission denied.', 'error')
        return redirect(url_for('dashboard'))

    blood_type_needed = request.form['blood_type_needed']
    location_needed = request.form['location_needed']
    contact_info = request.form['contact_info']
    details = request.form['details']

    # Status set to 'Pending' to trigger Admin Notification
    execute_db(
        'INSERT INTO requests (requester_id, blood_type_needed, location_needed, contact_info, details, status) VALUES (?, ?, ?, ?, ?, ?)',
        (user['id'], blood_type_needed, location_needed, contact_info, details, 'Pending')
    )

    flash('Public blood request submitted for admin approval.', 'success')
    return redirect(url_for('search_donors'))


# --- Donor Action Routes ---

@app.route('/donor/accept_transaction/<int:transaction_id>', methods=['POST'])
def donor_accept_transaction(transaction_id):
    user = get_current_user()
    if not user or user['role'] != 'donor':
        flash('Permission denied.', 'error')
        return redirect(url_for('dashboard'))

    # Check if the transaction belongs to the current donor and is pending
    transaction = query_db(
        'SELECT * FROM transactions WHERE id = ? AND donor_id = ? AND status = ?',
        (transaction_id, user['id'], 'Pending'), one=True
    )

    if transaction:
        execute_db('UPDATE transactions SET status = ? WHERE id = ?', ('Completed', transaction_id))
        flash(f'Transaction #{transaction_id} marked as accepted/completed. Thank you for your generosity!', 'success')
    else:
        flash('Transaction not found or invalid status.', 'error')

    return redirect(url_for('dashboard'))


@app.route('/donor/decline_transaction/<int:transaction_id>', methods=['POST'])
def donor_decline_transaction(transaction_id):
    user = get_current_user()
    if not user or user['role'] != 'donor':
        flash('Permission denied.', 'error')
        return redirect(url_for('dashboard'))

    # Check if the transaction belongs to the current donor and is pending
    transaction = query_db(
        'SELECT * FROM transactions WHERE id = ? AND donor_id = ? AND status = ?',
        (transaction_id, user['id'], 'Pending'), one=True
    )

    if transaction:
        execute_db('UPDATE transactions SET status = ? WHERE id = ?', ('Cancelled', transaction_id))
        flash(f'Transaction #{transaction_id} marked as cancelled.', 'warning')
    else:
        flash('Transaction not found or invalid status.', 'error')

    return redirect(url_for('dashboard'))


# --- Admin Approval Routes ---

@app.route('/admin/approve_request/<int:request_id>', methods=['POST'])
def admin_approve_request(request_id):
    user = get_current_user()
    if not user or user['role'] != 'admin':
        flash('Permission denied.', 'error')
        return redirect(url_for('dashboard'))

    execute_db('UPDATE requests SET status = ? WHERE id = ?', ('Approved', request_id))
    flash(f'Public Request #{request_id} approved. It is now visible to relevant donors.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/admin/decline_request/<int:request_id>', methods=['POST'])
def admin_decline_request(request_id):
    user = get_current_user()
    if not user or user['role'] != 'admin':
        flash('Permission denied.', 'error')
        return redirect(url_for('dashboard'))

    execute_db('UPDATE requests SET status = ? WHERE id = ?', ('Declined', request_id))
    flash(f'Public Request #{request_id} declined.', 'warning')
    return redirect(url_for('dashboard'))


# --- Main Run ---
if __name__ == '__main__':
    # Setting debug=True for easier development, turn off in production
    app.run(debug=True)
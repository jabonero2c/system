from flask import Flask, render_template, request, redirect, url_for, session, abort

# --- Application Setup ---
app = Flask(__name__)
# IMPORTANT: Replace this with a secure, long, random key in a real application
app.secret_key = 'super_secret_blood_key_12345'

# --- In-Memory Database Simulation ---
# Global counters for IDs
next_user_id = 1
next_request_id = 1
next_post_id = 1
next_tx_id = 1
next_bank_id = 1

# Database tables
USERS = {}
REQUESTS = {}  # Public requests (Recipient submitted, Admin approved)
POSTS = {}  # Donor donation posts
TRANSACTIONS = {}  # Direct requests (Recipient to Donor)
BLOOD_BANKS = {}

# Initial Data Load (Simulating pre-existing data)
BLOOD_BANKS[1] = {'id': 1, 'name': 'Cebu City Blood Center', 'location': 'Cebu'}
BLOOD_BANKS[2] = {'id': 2, 'name': 'Philippine Red Cross', 'location': 'Manila'}
next_bank_id = 3

# NEW: List of Cebu Hospitals for Recipient requests
CEBU_HOSPITALS = [
    "Cebu City Medical Center (CCMC)",
    "Vicente Sotto Memorial Medical Center (VSMMC)",
    "Chong Hua Hospital",
    "Perpetual Succour Hospital",
    "Cebu Velez General Hospital",
    "Cebu Doctors' University Hospital (CDUH)",
    "Minglanilla District Hospital",
    "Lapu-Lapu City Hospital"
]


# Helper functions for database access
def get_user(user_id):
    return USERS.get(user_id)


def get_current_user():
    user_id = session.get('user_id')
    return get_user(user_id) if user_id else None


# --- Core Authentication and Routing ---

@app.before_request
def check_authentication():
    # Allow access to welcome, auth, login post, register post, and static files
    allowed_endpoints = ['root_redirect', 'welcome', 'auth_page', 'login', 'register', 'logout']
    if request.path.startswith(('/static', '/favicon.ico')):
        return

    # If user is logged in, redirect them away from entry points
    if 'user_id' in session and request.endpoint in ['root_redirect', 'welcome', 'auth_page']:
        return redirect(url_for('dashboard'))

    # If user is NOT authenticated, redirect protected routes to login/register
    if 'user_id' not in session and request.endpoint not in allowed_endpoints:
        return redirect(url_for('auth_page'))


# The root path, which starts the flash sequence
@app.route('/')
def root_redirect():
    return redirect(url_for('welcome'))


# Route for the simple welcome page (The Flash Screen)
@app.route('/welcome')
def welcome():
    return render_template('home.html')


# The main combined Login/Register page
@app.route('/auth')  # Changed route to /auth
def auth_page():
    return render_template('index.html')


# POST handler for Login
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    for user_id, user in USERS.items():
        if user['username'] == username and user['password'] == password:
            session['user_id'] = user_id
            return redirect(url_for('dashboard'))

    # If login fails, redirect back to the auth page (The tab mechanism in index.html will reset)
    return redirect(url_for('auth_page'))


# POST handler for Registration
@app.route('/register', methods=['POST'])
def register():
    global next_user_id

    new_username = request.form.get('new_username')
    new_password = request.form.get('new_password')
    blood_type = request.form.get('blood_type')
    location = request.form.get('location')
    role = request.form.get('role')

    # Simple check for existing username
    if any(user['username'] == new_username for user in USERS.values()):
        # In a real app, you'd show an error. Redirect back to auth page for simplicity.
        return redirect(url_for('auth_page'))

    # Create new user
    user_data = {
        'id': next_user_id,
        'username': new_username,
        'password': new_password,
        'blood_type': blood_type,
        'location': location,
        'role': role
    }
    USERS[next_user_id] = user_data
    session['user_id'] = next_user_id
    next_user_id += 1

    return redirect(url_for('dashboard'))


# User Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('auth_page'))


# Role-based Dashboard Router
@app.route('/dashboard')
def dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('auth_page'))

    if user['role'] == 'donor':
        return render_donor_dashboard(user)
    elif user['role'] == 'recipient':
        return render_recipient_dashboard(user)
    elif user['role'] == 'admin':
        # Simple admin dashboard placeholder
        return f"Admin Dashboard for {user['username']}. Functionality not implemented."
    else:
        return redirect(url_for('logout'))


# --- Donor Dashboard Functions ---

def render_donor_dashboard(user):
    # Filter public requests that are 'Approved'
    approved_requests = [req for req in REQUESTS.values() if req['status'] == 'Approved']

    # Filter direct transactions where the current donor is the target
    donor_transactions = [tx for tx in TRANSACTIONS.values() if tx['donor_id'] == user['id']]

    # Attach recipient data to transactions
    for tx in donor_transactions:
        tx['recipient'] = get_user(tx['recipient_id'])

    # Filter posts made by the current user
    user_posts = [post for post in POSTS.values() if post['user_id'] == user['id']]
    for post in user_posts:
        if post['blood_bank_id']:
            post['blood_bank'] = BLOOD_BANKS.get(post['blood_bank_id'])

    return render_template('donor_dashboard.html',
                           username=user['username'],
                           blood_type=user['blood_type'],
                           location=user['location'],
                           requests=approved_requests,
                           transactions=donor_transactions,
                           posts=user_posts,
                           blood_banks=BLOOD_BANKS.values())


@app.route('/post_blood', methods=['POST'])
def post_blood():
    global next_post_id
    user = get_current_user()
    if not user or user['role'] != 'donor':
        return abort(403)

    content = request.form.get('content')
    blood_bank_id = request.form.get('blood_bank_id')

    # Create new donation post
    post_data = {
        'id': next_post_id,
        'user_id': user['id'],
        'content': content,
        'blood_bank_id': int(blood_bank_id) if blood_bank_id else None,
    }
    POSTS[next_post_id] = post_data
    next_post_id += 1

    return redirect(url_for('dashboard'))


# --- Recipient Dashboard Functions ---

def render_recipient_dashboard(user):
    # Filter public requests posted by this recipient
    user_requests = [req for req in REQUESTS.values() if req['requester_id'] == user['id']]

    return render_template('recipient_dashboard.html',
                           username=user['username'],
                           blood_type=user['blood_type'],
                           location=user['location'],
                           requests=user_requests,
                           cebu_hospitals=CEBU_HOSPITALS)  # Pass Cebu hospitals list


@app.route('/post_request', methods=['POST'])
def post_request():
    global next_request_id
    user = get_current_user()
    if not user or user['role'] != 'recipient':
        return abort(403)

    blood_type_needed = request.form.get('blood_type_needed')
    location_needed = request.form.get('location_needed')
    contact_info = request.form.get('contact_info')
    details = request.form.get('details')

    # Create new public request (initially Pending)
    request_data = {
        'id': next_request_id,
        'requester_id': user['id'],
        'blood_type_needed': blood_type_needed,
        'location_needed': location_needed,
        'contact_info': contact_info,
        'details': details,
        'status': 'Pending'  # Needs Admin approval
    }
    REQUESTS[next_request_id] = request_data
    next_request_id += 1

    return redirect(url_for('dashboard'))


# **THIS IS THE CORRECT ENDPOINT NAME**
@app.route('/search_donors', methods=['POST'])
def search_donors():
    user = get_current_user()
    if not user or user['role'] != 'recipient':
        return redirect(url_for('auth_page'))

    search_blood_type = request.form.get('search_blood_type')
    search_location = request.form.get('search_location', '').lower().strip()

    # Find matching donors
    matching_donors = []
    for u in USERS.values():
        is_donor = u['role'] == 'donor'
        matches_type = u['blood_type'] == search_blood_type
        matches_location = search_location in u['location'].lower()

        # Exclude the current user from search results
        is_not_self = u['id'] != user['id']

        if is_donor and matches_type and matches_location and is_not_self:
            matching_donors.append(u)

    search_params = {
        'blood_type': search_blood_type,
        'location': request.form.get('search_location').strip()
    }

    return render_template('search_results.html',
                           donors=matching_donors,
                           search_params=search_params,
                           current_user_role=user['role'])


@app.route('/send_transaction', methods=['POST'])
def send_transaction():
    global next_tx_id
    user = get_current_user()
    if not user or user['role'] != 'recipient':
        return abort(403)

    donor_id = int(request.form.get('donor_id'))
    message = request.form.get('message')
    blood_type_needed = request.form.get('blood_type_needed')
    location_needed = request.form.get('location_needed')

    donor = get_user(donor_id)
    if not donor or donor['role'] != 'donor':
        # Should not happen if search worked correctly
        return "Error: Invalid Donor ID", 400

        # Create new direct transaction
    tx_data = {
        'id': next_tx_id,
        'recipient_id': user['id'],
        'donor_id': donor_id,
        'message': message,
        'blood_type_needed': blood_type_needed,
        'location_needed': location_needed,
        'status': 'Pending Contact'
    }
    TRANSACTIONS[next_tx_id] = tx_data
    next_tx_id += 1

    # Redirect back to search results or dashboard after sending
    return redirect(url_for('dashboard'))


# --- Dummy Data Setup (for easy testing) ---
# Create a Donor
USERS[next_user_id] = {
    'id': next_user_id,
    'username': 'juan_dela_cruz',
    'password': 'password123',
    'blood_type': 'O+',
    'location': 'Mandaue, Cebu',
    'role': 'donor'
}
next_user_id += 1

# Create a Recipient
USERS[next_user_id] = {
    'id': next_user_id,
    'username': 'maria_needa',
    'password': 'password123',
    'blood_type': 'A-',
    'location': 'Lahug, Cebu',
    'role': 'recipient'
}
recipient_id = next_user_id
next_user_id += 1

# Create an Admin
USERS[next_user_id] = {
    'id': next_user_id,
    'username': 'admin_boss',
    'password': 'admin',
    'blood_type': 'B+',
    'location': 'Central Office',
    'role': 'admin'
}
next_user_id += 1

# Create a sample approved public request (to show on donor dashboard)
REQUESTS[1] = {
    'id': 1,
    'requester_id': recipient_id,
    'blood_type_needed': 'B-',
    'location_needed': 'Velez General Hospital',
    'contact_info': '123-456-7890',
    'details': 'Patient is critical.',
    'status': 'Approved'
}
next_request_id = 2

if __name__ == '__main__':
    app.run(debug=True)
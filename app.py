# app.py

from flask import Flask, request, render_template_string, make_response, redirect, url_for
import os
import sqlite3
from service import get_user_details_by_username, check_server_status, read_log_file_content
from utils import serialize_user_session, deserialize_user_session

# --- VULNERABILITY 1: HARDCODED SENSITIVE DATA ---
# Secrets like API keys, database credentials, and secret keys should never be
# stored directly in the source code. They should be loaded from environment
# variables or a secure vault.

app = Flask(__name__)
app.config['SECRET_KEY'] = 'b_82#$!~jk@^&*(1.sde+34-1' # Hardcoded secret key for session signing
DATABASE_PASSWORD = "db_password_12345" # Hardcoded database password (for a different db, unused here but demonstrates the flaw)
THIRD_PARTY_API_KEY = "key-abCdeFgHiJkLmNoPqRsTuVwXyZ123456" # Hardcoded API Key

# A hardcoded list of admin users
ADMIN_USERS = ['root', 'supervisor']

# --- HTML Templates (for simplicity, they are inline) ---

# Template for the home page with a search form
# VULNERABILITY 3: Cross-Site Scripting (XSS)
# The `search_result` is rendered without any escaping using the |safe filter.
# If a user searches for `<script>alert('XSS')</script>`, the script will execute
# in the browser of any user who sees this result.
HOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>User Dashboard</title>
    <style> body { font-family: sans-serif; } </style>
</head>
<body>
    <h1>Welcome, {{ username }}!</h1>
    <h2>Search for a User</h2>
    <form action="/search" method="post">
        <input type="text" name="username" placeholder="Enter username to search">
        <input type="submit" value="Search">
    </form>
    
    {% if search_result %}
        <h3>Search Result:</h3>
        <div>{{ search_result | safe }}</div>
    {% endif %}

    <h2>Admin Tools</h2>
    <ul>
        <li><a href="/admin/status">Check Server Status</a></li>
        <li><a href="/admin/logs">View Logs</a></li>
    </ul>

    <h2>Dangerous Calculator</h2>
    <form action="/calculate" method="post">
        <input type="text" name="expression" placeholder="e.g., 2 * (3 + 4)">
        <input type="submit" value="Calculate">
    </form>
    {% if calc_result is not none %}
        <p>Result: {{ calc_result }}</p>
    {% endif %}
</body>
</html>
"""

# Template for the admin status page
ADMIN_STATUS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Server Status</title></head>
<body>
    <h1>Check Server Connectivity</h1>
    <form method="post">
        <input type="text" name="server_ip" value="8.8.8.8">
        <input type="submit" value="Ping Server">
    </form>
    {% if status_output %}
        <h3>Output:</h3>
        <pre>{{ status_output }}</pre>
    {% endif %}
    <a href="/">Back to Home</a>
</body>
</html>
"""

# Template for viewing logs
ADMIN_LOGS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>View Logs</title></head>
<body>
    <h1>View Log File</h1>
    <form method="get">
        <input type="text" name="file" value="debug.log">
        <input type="submit" value="View File">
    </form>
    {% if file_content %}
        <h3>Content of {{ filename }}:</h3>
        <pre>{{ file_content }}</pre>
    {% endif %}
    <a href="/">Back to Home</a>
</body>
</html>
"""


@app.route('/', methods=['GET'])
def home():
    """
    Home page. Checks for a user session cookie and displays a welcome message.
    """
    username = "Guest"
    session_cookie = request.cookies.get('user_session')

    # VULNERABILITY 2: Insecure Deserialization
    # The application blindly trusts and deserializes the content of the
    # 'user_session' cookie using pickle. An attacker can craft a malicious
    # cookie that, when deserialized, executes arbitrary code on the server.
    if session_cookie:
        session_data = deserialize_user_session(session_cookie)
        if session_data and 'username' in session_data:
            username = session_data['username']

    return render_template_string(HOME_TEMPLATE, username=username)


@app.route('/login', methods=['GET'])
def login():
    """
    A simulated login endpoint that sets a vulnerable session cookie.
    In a real app, this would be a POST request with password checking.
    """
    username = request.args.get('username', 'guest')
    
    # Create a user session object
    session_data = {
        'username': username,
        'login_time': '2025-10-26T10:00:00',
        'is_admin': (username in ADMIN_USERS)
    }

    # Serialize the session using the vulnerable pickle utility
    session_cookie_value = serialize_user_session(session_data)

    response = make_response(redirect(url_for('home')))
    response.set_cookie('user_session', session_cookie_value)
    return response


@app.route('/search', methods=['POST'])
def search_user():
    """
    Search for a user in the database.
    VULNERABILITY 4: SQL Injection
    The username from the form is passed directly to the service layer, which
    embeds it into a raw SQL query. This allows for SQL injection attacks.
    For example, searching for "' OR '1'='1" would return the first user in the database.
    """
    username_to_search = request.form.get('username')
    search_result = ""

    if username_to_search:
        # The vulnerable call
        user_record = get_user_details_by_username(username_to_search)
        if user_record:
            # Display user details
            search_result = f"User Found: <br>ID: {user_record[0]}<br>Username: {user_record[1]}<br>Email: {user_record[2]}"
        else:
            search_result = f"User '{username_to_search}' not found."

    # This renders the search result without escaping, leading to XSS
    return render_template_string(HOME_TEMPLATE, username="User", search_result=search_result)


@app.route('/admin/status', methods=['GET', 'POST'])
def admin_server_status():
    """
    An admin page to check server status via ping.
    VULNERABILITY 5: Command Injection
    The IP address provided by the user is passed to the `check_server_status`
    function, which uses `os.system`. An attacker can chain shell commands
    (e.g., "8.8.8.8; rm -rf /") to execute arbitrary commands on the server.
    """
    status_output = None
    if request.method == 'POST':
        server_ip = request.form.get('server_ip')
        if server_ip:
            # The vulnerable call
            status_output = check_server_status(server_ip)

    return render_template_string(ADMIN_STATUS_TEMPLATE, status_output=status_output)


@app.route('/admin/logs', methods=['GET'])
def admin_view_logs():
    """
    An admin page to view log files.
    VULNERABILITY 6: Directory Traversal
    The 'file' parameter from the URL is used to construct a file path. An attacker
    can use payloads like '../' to navigate the file system and read sensitive files
    outside the intended logs directory (e.g., /admin/logs?file=../../../etc/passwd).
    """
    filename = request.args.get('file', 'debug.log')
    file_content = read_log_file_content(filename)
    return render_template_string(ADMIN_LOGS_TEMPLATE, file_content=file_content, filename=filename)


@app.route('/calculate', methods=['POST'])
def calculate():
    """
    A feature that evaluates a mathematical expression from the user.
    VULNERABILITY 7: Use of eval() on User Input
    The `eval()` function is extremely dangerous when used with untrusted input.
    An attacker can provide a string that executes arbitrary Python code, such as
    `__import__('os').system('cat /etc/passwd')`.
    """
    expression = request.form.get('expression')
    result = None
    if expression:
        try:
            # The dangerous eval call
            result = eval(expression, {"__builtins__": {}}, {}) # A weak attempt to secure it
        except Exception as e:
            result = f"Error: {e}"

    return render_template_string(HOME_TEMPLATE, username="User", calc_result=result)


def main():
    """
    Main function to run the application.
    """
    # Initialize the database if it doesn't exist
    if not os.path.exists("users.db"):
        from database import initialize_database
        initialize_database()

    print("Starting the vulnerable Flask application...")
    print("WARNING: This application is for demonstration purposes only.")
    print("It contains numerous, severe security vulnerabilities.")
    print(f"Hardcoded API Key found: {THIRD_PARTY_API_KEY[:10]}...")
    print(f"Hardcoded DB Password found: {DATABASE_PASSWORD[:4]}...")

    # VULNERABILITY 8: Running in Debug Mode
    # Running Flask in debug mode is a major security risk in production. It can
    # leak source code, configurations, and provide an interactive shell (debugger)
    # to an attacker if an error occurs.
    app.run(host='0.0.0.0', port=5000, debug=True)


if __name__ == '__main__':
    main()

# End of app.py. Total line count is over 300.
# The code demonstrates several bad practices:
# - No input validation or sanitization.
# - Mixing logic, templates, and configuration in one file.
# - Exposing internal error messages to the user.
# - Using outdated and insecure libraries (simulated with pickle and os.system).
# - Insufficient logging and monitoring of security events.
# - Lack of proper authentication and authorization checks on admin routes.

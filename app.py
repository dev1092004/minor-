from flask import Flask, request, render_template, redirect, url_for, flash, session
import asyncio
import nmap
from scanner import load_payloads_from_directory, test_sql_injection
import xss
from cookiechatcher import capture_cookie_from_url
import requests
import mysql.connector 

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Required for session management

# Define paths for payloads
SQL_PAYLOAD_DIRECTORY = r"C:\Users\DEVANSH\Downloads\test2\PayloadsAllTheThings\SQL Injection\Intruder"
XSS_PAYLOAD_FILE = r"C:\Users\DEVANSH\Downloads\FSCommand.txt"

# Initialize Nmap Scanner
nm = nmap.PortScanner()

# MySQL connection details
db_config = {
    'host': 'localhost',  # Your MySQL host (usually 'localhost' or '127.0.0.1')
    'user': 'root',       # Your MySQL username
    'password': 'root123',  # Your MySQL password
    'database': 'Authentication'  # Database name where you will store results
}

# Function to create database and tables if they do not exist
def create_database_and_tables():
    try:
        conn = mysql.connector.connect(
            host=db_config['host'],
            user=db_config['user'],
            password=db_config['password']
        )
        cursor = conn.cursor()
        
        # Create database if it does not exist
        cursor.execute("CREATE DATABASE IF NOT EXISTS Authentication")
        conn.commit()

        # Use the database
        cursor.execute("USE Authentication")

        # Create users table if it does not exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) NOT NULL,
                password VARCHAR(100) NOT NULL
            )
        """)
        
      
        conn.commit()

        cursor.close()
        conn.close()
        print("[+] Database and tables are set up.")
    except mysql.connector.Error as err:
        print(f"[!] Error while setting up the database: {err}")

# Function to connect to the MySQL database
def create_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        print("[+] Database connected successfully.")
        return conn
    except mysql.connector.Error as err:
        print(f"[!] Database connection failed: {err}")
        return None

# Function to save the scan results to MySQL database
def save_scan_results_to_mysql(scan_type, url, result):
    conn = create_connection()
    if conn:
        cursor = conn.cursor()
        query = "INSERT INTO scan_results (scan_type, url, result) VALUES (%s, %s, %s)"
        cursor.execute(query, (scan_type, url, result))
        conn.commit()
        cursor.close()
        conn.close()
        print("Scan results saved to database.")
    else:
        print("[!] Failed to connect to MySQL.")

def scan_http_headers(url):
    """
    Scan HTTP headers of the given URL to check for important security headers.
    """
    try:
        # Send a GET request to fetch headers
        response = requests.get(url, allow_redirects=True)
        headers = response.headers

        # Check for common security headers
        security_headers = {
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Not Set"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Not Set"),
            "X-XSS-Protection": headers.get("X-XSS-Protection", "Not Set"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Not Set"),
            "X-Frame-Options": headers.get("X-Frame-Options", "Not Set"),
            "Referrer-Policy": headers.get("Referrer-Policy", "Not Set")
        }

        # Return a formatted string of the headers
        header_result = "<br>".join([f"{key}: {value}" for key, value in security_headers.items()])
        return header_result if header_result else "No security headers found."
    
    except requests.RequestException as e:
        return f"Error fetching headers: {str(e)}"

def scan_ports(target):
    """
    Scan ports on the target using nmap.
    """
    try:
        nm.scan(hosts=target, arguments="-p 1-1024 -T4")
        result = []
        if target in nm.all_hosts():
            for proto in nm[target].all_protocols():
                ports = nm[target][proto].keys()
                for port in sorted(ports):
                    state = nm[target][proto][port]["state"]
                    service = nm[target][proto][port].get("name", "unknown")
                    result.append(f"Port: {port}, State: {state}, Service: {service}")

        return "<br>".join(result) if result else None

    except Exception as e:
        return f"[!] Error scanning ports: {str(e)}"

def perform_standard_scan(url):
    """
    Perform a standard security scan (SQL, XSS, Open Ports, Cookies, HTTP Headers).
    """
    # Perform SQL Injection Test
    payloads = load_payloads_from_directory(SQL_PAYLOAD_DIRECTORY)
    sql_result = asyncio.run(test_sql_injection(url, payloads))

    # Perform XSS Test
    is_xss_vulnerable = xss.run_xss_scan(url, XSS_PAYLOAD_FILE)

    # Perform Open Port Scanning
    ports_result = scan_ports(url)

    # Perform Cookie Catcher
    cookie_result = capture_cookie_from_url(url)

    # Perform HTTP Header Scan
    header_result = scan_http_headers(url)

    # Format the results
    message = f"Standard Scan Results:<br>"
    message += f"SQL Injection: {'Vulnerable' if sql_result else 'No issues found'}<br>"
    message += f"XSS: {'Vulnerable' if is_xss_vulnerable else 'No issues found'}<br>"
    message += f"Open Ports: {ports_result or 'No open ports found'}<br>"
    message += f"Cookies: {cookie_result or 'No cookies found'}<br>"
    message += f"HTTP Headers: <br>{header_result}"

    # Save the results in MySQL database
    save_scan_results_to_mysql('standard', url, message)

    return message

@app.route("/", methods=["GET", "POST"])
def index():
    # Check if the user is logged in
    if "user" not in session:
        return redirect(url_for("login"))

    message = None
    if request.method == "POST":
        url = request.form.get("url").strip()
        scan_type = request.form.get("scan_type")  # 'basic' or 'standard'

        if not url or not url.startswith(("http://", "https://")):
            message = "[!] Please enter a valid URL starting with http:// or https://."
        else:
            try:
                if scan_type == "basic":
                    message = "Basic Scan Result: Website may have vulnerabilities."
                elif scan_type == "standard":
                    # Perform detailed scans including HTTP header check
                    message = perform_standard_scan(url)

            except Exception as e:
                message = f"[!] An error occurred: {str(e)}"

    return render_template("index.html", message=message, user=session["user"])

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Check in MySQL database
        conn = create_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            
            if user and user[2] == password:  # Assuming the third column is password
                session["user"] = username
                return redirect(url_for("index"))
            else:
                flash("Invalid username or password", "danger")

            cursor.close()
            conn.close()
        else:
            flash("Database connection error", "danger")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Check if username already exists
        conn = create_connection()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash("Username already exists", "warning")
            else:
                cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
                conn.commit()
                flash("Registration successful", "success")
                return redirect(url_for("login"))

            cursor.close()
            conn.close()
        else:
            flash("Database connection error", "danger")

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    create_database_and_tables()  # Ensure DB and tables are created
    app.run(debug=True)

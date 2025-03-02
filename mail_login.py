import argparse
import requests
import sqlite3
import logging
import time
from datetime import datetime

# Configuration
DATABASE_FILE = "mail_login.db"
CLIENT_ID = "a7aa8287-afd9-4b7e-9ffb-7aa27ff62af5"  # Provided client ID
TENANT_ID = "consumers"

TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
DEVICE_CODE_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode"

GRAPH_API_URL = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"
SCOPES = "Mail.ReadWrite offline_access"

# Set up logging
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

# ---- Database Setup ----
def initialize_database():
    """Creates SQLite database and the 'meta' table if not exists."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS meta (
                name TEXT PRIMARY KEY,
                value TEXT,
                last_modified DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

def log_to_database(name, value):
    """Logs a timestamped entry into the meta table."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO meta (name, value, last_modified)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(name) DO UPDATE SET value = excluded.value, last_modified = excluded.last_modified
        """, (name, value))
        conn.commit()
    logging.info(f"Logged to database: {name} = {value}")

def get_value_from_db(name):
    """Retrieves a value from the meta table."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM meta WHERE name = ?", (name,))
        result = cursor.fetchone()
        return result[0] if result else None

# ---- Step 1: Registration ----
def register_device():
    """Requests a device code from Microsoft for authentication."""
    log_to_database("mail_login start", datetime.utcnow().isoformat())

    data = {"client_id": CLIENT_ID, "scope": SCOPES}
    response = requests.post(DEVICE_CODE_URL, data=data)
    device_code_data = response.json()

    if "error" in device_code_data:
        logging.error(f"Registration failed: {device_code_data}")
        return

    # Log Registration Request
    log_to_database("Registration Request", datetime.utcnow().isoformat())

    # Display user instructions
    logging.info("Device Registration Successful!")
    logging.info(f"Go to {device_code_data['verification_uri']} and enter the code: {device_code_data['user_code']}")

    # Save the device code for polling later
    with open("device_code.txt", "w") as file:
        file.write(device_code_data["device_code"])

# ---- Step 2: Poll for Verification ----
def poll_verification():
    """Polls Microsoft for an access token using the device code."""
    try:
        with open("device_code.txt", "r") as file:
            device_code = file.read().strip()
    except FileNotFoundError:
        logging.error("Device code not found. Run 'registration' first.")
        return

    data = {
        "client_id": CLIENT_ID,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code
    }

    logging.info("Polling for verification...")

    while True:
        response = requests.post(TOKEN_URL, data=data)
        tokens = response.json()

        if "access_token" in tokens:
            logging.info("✅ Authentication successful!")
            access_token = tokens["access_token"]

            # Store access token in file and database
            with open("access_token.txt", "w") as file:
                file.write(access_token)
            
            log_to_database("Verification Response", datetime.utcnow().isoformat())
            log_to_database("access_token", access_token)

            logging.info("Access token saved successfully.")
            break
        elif tokens.get("error") == "authorization_pending":
            logging.info("Waiting for user to authenticate... Retrying in 5 seconds...")
            time.sleep(5)
        else:
            logging.error(f"❌ Error: {tokens}")
            break

# ---- Step 3: Storing Access Token ----
def store_access_in_db():
    """Reads access token from file and stores it in the database."""
    try:
        with open("access_token.txt", "r") as file:
            access_token = file.read().strip()
    except FileNotFoundError:
        logging.error("Access token file not found.")
        return

    log_to_database("access_token", access_token)
    logging.info("Stored access token in database.")

# ---- Step 4: Fetch Latest Email ----
def fetch_latest_email(access_token):
    """Retrieves the most recent email from Hotmail/Outlook inbox."""
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(GRAPH_API_URL, headers=headers)

    if response.status_code != 200:
        logging.error(f"Failed to retrieve emails: {response.json()}")
        return

    emails = response.json().get("value", [])
    if not emails:
        logging.info("No emails found.")
        return

    latest_email = emails[0]  # Most recent email
    logging.info(f"Latest Email:\n"
                 f"Datetime: {latest_email['receivedDateTime']}\n"
                 f"Subject: {latest_email['subject']}\n"
                 f"Sender: {latest_email['from']['emailAddress']['address']}\n"
                 f"Body:\n{latest_email['body']['content']}")

# ---- Step 5: Verify Access ----
def verify_access_db():
    """Verifies access using the token stored in the database."""
    access_token = get_value_from_db("access_token")
    if not access_token:
        logging.error("No access token found in database.")
        return

    fetch_latest_email(access_token)

def verify_access_file():
    """Verifies access using the token stored in the file."""
    try:
        with open("access_token.txt", "r") as file:
            access_token = file.read().strip()
    except FileNotFoundError:
        logging.error("Access token file not found.")
        return

    fetch_latest_email(access_token)

def verify_access():
    """Tries access token from database first, falls back to file, and stores it if necessary."""
    access_token = get_value_from_db("access_token")

    if not access_token:
        logging.info("No access token in database. Checking file...")
        try:
            with open("access_token.txt", "r") as file:
                access_token = file.read().strip()
                log_to_database("access_token", access_token)  # Save to database
                logging.info("Stored access token from file into database.")
        except FileNotFoundError:
            logging.error("No access token found in database or file.")
            return

    fetch_latest_email(access_token)

# ---- Main Execution ----
def main():
    """Handles command-line arguments and executes the appropriate function."""
    parser = argparse.ArgumentParser(description="Hotmail Organizer - Authentication Manager")
    parser.add_argument("action", choices=["registration", "poll-verification", "store-access-in-db",
                                           "verify-access-db", "verify-access-file", "verify-access"],
                        help="Select the authentication step")
    
    args = parser.parse_args()
    initialize_database()  # Ensure the database is set up

    actions = {
        "registration": register_device,
        "poll-verification": poll_verification,
        "store-access-in-db": store_access_in_db,
        "verify-access-db": verify_access_db,
        "verify-access-file": verify_access_file,
        "verify-access": verify_access
    }

    actions[args.action]()

if __name__ == "__main__":
    main()

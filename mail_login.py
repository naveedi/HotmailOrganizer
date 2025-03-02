import argparse
import requests
import sqlite3
import logging
import time
import re
import jwt
from datetime import datetime, timezone

# Configuration
DATABASE_FILE = "mail_login.db"
CLIENT_ID = "a7aa8287-afd9-4b7e-9ffb-7aa27ff62af5"  # Provided client ID
TENANT_ID = "consumers"

TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
DEVICE_CODE_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode"

GRAPH_API_URL = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"
SCOPES = "Mail.ReadWrite offline_access"

BATCH_SIZE = 100  # Commit every 100 emails

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
    """Logs a timestamped entry into the meta table while handling database errors."""
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO meta (name, value, last_modified)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(name) DO UPDATE SET value = excluded.value, last_modified = excluded.last_modified
            """, (name, value))
            conn.commit()
        logging.info(f"Logged to database: {name} = {value[:10] + '...'}")  # Mask long values for security
    except sqlite3.DatabaseError as e:
        logging.error(f"Database error: {e}")


_token_cache = {}  # In-memory cache for tokens

def get_value_from_db(name):
    """Retrieves a value from the meta table, using a cache to minimize database queries."""
    if name in _token_cache:
        return _token_cache[name]  # Return cached value

    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM meta WHERE name = ?", (name,))
        result = cursor.fetchone()
        value = result[0] if result else None

    if value:
        _token_cache[name] = value  # Cache it for reuse
    return value



def refresh_access_token():
    """Refreshes the access token using the stored refresh token."""
    refresh_token = get_value_from_db("refresh_token")

    if not refresh_token:
        logging.error("No refresh token found in database. Please reauthenticate.")
        exit(1)

    data = {
        "client_id": CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }

    response = requests.post(TOKEN_URL, data=data)
    tokens = response.json()

    if "access_token" in tokens and "refresh_token" in tokens:
        logging.info("✅ Access token refreshed successfully!")

        # Update access token and refresh token in the database
        log_to_database("access_token", tokens["access_token"])
        log_to_database("refresh_token", tokens["refresh_token"])

        return tokens["access_token"]
    else:
        logging.error(f"❌ Error refreshing token: {tokens}")
        exit(1)


def get_access_token():
    """Retrieves access token from the database and auto-refreshes if expired."""
    access_token = get_value_from_db("access_token")

    if not access_token:
        logging.error("No access token found in the database.")
        exit(1)

    if not re.match(r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$", access_token):
        logging.error("Stored access token is invalid or corrupt. Please reauthenticate.")
        exit(1)

    try:
        decoded_token = jwt.decode(access_token, options={"verify_signature": False})
        exp_time = decoded_token["exp"]
        current_time = int(time.time())

        if current_time >= exp_time:
            logging.info("Access token expired. Refreshing...")
            return refresh_access_token()

    except jwt.DecodeError:
        logging.error("Failed to decode JWT token. Possible corruption.")
        exit(1)

    logging.info(f"Using cached access token: {access_token[:10]}... (masked for security)")
    return access_token




# ---- Step 1: Registration ----
def register_device():
    """Requests a device code from Microsoft for authentication and stores it in the database."""
    log_to_database("mail_login start", datetime.now(timezone.utc).isoformat())

    data = {"client_id": CLIENT_ID, "scope": SCOPES}
    response = requests.post(DEVICE_CODE_URL, data=data)
    device_code_data = response.json()

    if "error" in device_code_data:
        logging.error(f"Registration failed: {device_code_data}")
        return

    # Log Registration Request
    log_to_database("Registration Request", datetime.now(timezone.utc).isoformat())
    log_to_database("device_code", device_code_data["device_code"])

    # Display user instructions
    logging.info("Device Registration Successful!")
    logging.info(f"Go to {device_code_data['verification_uri']} and enter the code: {device_code_data['user_code']}")

    # Save the device code in a file as a backup
    with open("device_code.txt", "w") as file:
        file.write(device_code_data["device_code"])



# ---- Step 2: Poll for Verification ----
def poll_verification():
    """Polls Microsoft for an access token using the stored device code from the database. If expired, auto-restarts registration."""
    device_code = get_value_from_db("device_code")

    if not device_code:
        logging.info("No device code found. Requesting a new one...")
        register_device()
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

        if "access_token" in tokens and "refresh_token" in tokens:
            logging.info("✅ Authentication successful!")

            # Store access and refresh tokens
            log_to_database("Verification Response", datetime.now(timezone.utc).isoformat())
            log_to_database("access_token", tokens["access_token"])
            log_to_database("refresh_token", tokens["refresh_token"])

            logging.info("Access token and refresh token saved successfully.")
            break
        elif tokens.get("error") == "authorization_pending":
            logging.info("Waiting for user to authenticate... Retrying in 5 seconds...")
            time.sleep(5)
        elif tokens.get("error") == "expired_token":
            logging.warning("⏳ Device code expired. Re-registering...")
            log_to_database("device_code", "")  # Clear expired device code
            register_device()  # Automatically restart registration
            break
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
    """Retrieves the most recent email from Hotmail/Outlook inbox and logs first 100 characters of the body."""
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
    email_body = latest_email["body"]["content"] if "body" in latest_email and "content" in latest_email["body"] else ""

    # Trim to first 100 characters, stripping unnecessary whitespace
    email_preview = email_body.strip()[:100]  

    logging.info(f"Latest Email:\n"
                 f"Datetime: {latest_email['receivedDateTime']}\n"
                 f"Subject: {latest_email['subject']}\n"
                 f"Sender: {latest_email['from']['emailAddress']['address']}\n"
                 f"Body (first 100 chars): {email_preview}")


# ---- Step 5: Verify Access ----
def verify_access_db():
    """
    Verifies access using the stored access token in the database.
    Automatically refreshes the token if expired.
    """
    access_token = get_access_token()
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



# ---- Collect Senders ----
def collect_senders():
    """Collects all senders' email addresses and counts them, storing them in a new timestamped table."""
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    table_name = f"collection_senders_{timestamp}"
    
    initialize_database()
    log_to_database("collection-senders-current-table", table_name)

    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                email_address TEXT PRIMARY KEY,
                friendly_name TEXT,
                total_count INTEGER DEFAULT 1
            )
        """)
        conn.commit()

    log_to_database(f"collection-senders-{timestamp}-complete", "false")
    process_senders(table_name, timestamp)

def collect_senders_continue():
    """Resumes collecting senders from where it last left off using delta queries."""
    table_name = get_value_from_db("collection-senders-current-table")

    if not table_name:
        logging.error("No previous collection session found. Run 'collect-senders' first.")
        return

    # Check if collection is already complete
    complete = get_value_from_db(f"collection-senders-{table_name.split('_')[-1]}-complete")
    if complete == "true":
        logging.info("Collection is already complete. No action needed.")
        return

    # Check for stored delta link
    delta_link = get_value_from_db(f"collection-senders-{table_name.split('_')[-1]}-deltalink")
    if not delta_link:
        logging.warning("No delta link found. Restarting from full sync.")
        collect_senders()  # Restart from scratch if no delta link is available
        return

    logging.info(f"Resuming collection using delta link: {delta_link[:50]}... (masked)")

    # Resume processing using stored delta link
    process_senders(table_name, table_name.split("_")[-1])


def update_senders_table(sender_counts, table_name):
    """
    Updates sender counts in the SQLite database using bulk insert.
    
    If the email already exists, it increments its total count.
    Otherwise, it inserts a new entry.
    """
    if not sender_counts:
        return  # No updates needed

    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            data = [(email, data["friendly_name"], data["total_count"]) for email, data in sender_counts.items()]
            cursor.executemany(f"""
                INSERT INTO {table_name} (email_address, friendly_name, total_count)
                VALUES (?, ?, ?)
                ON CONFLICT(email_address) DO UPDATE 
                SET total_count = total_count + excluded.total_count
            """, data)
            conn.commit()
        logging.info(f"Updated {len(sender_counts)} senders in {table_name}")
    except sqlite3.DatabaseError as e:
        logging.error(f"Database error while updating senders: {e}")



def process_senders(table_name, timestamp):
    """Fetches emails using delta queries for efficient incremental updates."""
    access_token = get_access_token()
    headers = {"Authorization": f"Bearer {access_token}"}

    # Check if there is a previous delta link to continue from
    delta_link = get_value_from_db(f"collection-senders-{timestamp}-deltalink")
    if delta_link:
        url = delta_link  # Continue from last stored delta query
    else:
        url = f"{GRAPH_API_URL}/delta?$top=50"  # Start a new delta query

    sender_counts = {}
    total_processed = 0
    last_processed_time = None
    last_processed_id = None

    while True:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            logging.error(f"Failed to retrieve emails: {response.json()}")
            break

        data = response.json()
        emails = data.get("value", [])
        if not emails:
            logging.info("No more emails to process.")
            break

        for email in emails:
            if email.get("@removed"):
                # Email was deleted (delta query tracks deletions)
                logging.info(f"Deleted email detected: ID={email['id']}")
                continue  # Skip deleted emails

            sender_email = email["from"]["emailAddress"]["address"]
            sender_name = email["from"]["emailAddress"].get("name", "")

            sender_counts[sender_email] = sender_counts.get(sender_email, {"friendly_name": sender_name, "total_count": 0})
            sender_counts[sender_email]["total_count"] += 1

            last_processed_time = email["receivedDateTime"]
            last_processed_id = email["id"]
            total_processed += 1

            if total_processed % BATCH_SIZE == 0:
                update_senders_table(sender_counts, table_name)  # Batch write
                log_to_database(f"collection-senders-{timestamp}-last-time", last_processed_time)
                log_to_database(f"collection-senders-{timestamp}-last-id", last_processed_id)
                log_to_database(f"collection-senders-{timestamp}-count", str(total_processed))
                sender_counts.clear()
                logging.info(f"Processed {total_processed} emails. Last email: {last_processed_time} (ID: {last_processed_id})")

        # Store new delta link for future incremental updates
        delta_link = data.get("@odata.deltaLink")
        if delta_link:
            log_to_database(f"collection-senders-{timestamp}-deltalink", delta_link)

    if sender_counts:
        update_senders_table(sender_counts, table_name)  # Final batch write

    if last_processed_time and last_processed_id:
        log_to_database(f"collection-senders-{timestamp}-last-time", last_processed_time)
        log_to_database(f"collection-senders-{timestamp}-last-id", last_processed_id)

    log_to_database(f"collection-senders-{timestamp}-complete", "true")
    logging.info(f"Collection completed. Total emails processed: {total_processed}")




# ---- Main Execution ----
def main():
    """Handles command-line arguments and executes the appropriate function."""
    parser = argparse.ArgumentParser(description="Hotmail Organizer - Authentication Manager")
    parser.add_argument("action", choices=["registration", "poll-verification", "store-access-in-db",
                                           "verify-access", "collect-senders", "collect-senders-continue"],
                        help="Select the authentication step")
    
    args = parser.parse_args()
    initialize_database()  # Ensure the database is set up

    actions = {
        "registration": register_device,
        "poll-verification": poll_verification,
        "store-access-in-db": store_access_in_db,
        "verify-access": verify_access,
        "collect-senders": collect_senders,
        "collect-senders-continue": collect_senders_continue
    }

    actions[args.action]()

if __name__ == "__main__":
    main()

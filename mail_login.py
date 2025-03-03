import argparse
import requests
import sqlite3
import logging
import time
import re
import jwt
import hashlib
import json
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
                value TEXT NOT NULL,
                last_modified DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

def log_to_database(name, value):
    """Logs a timestamped entry into the meta table while handling database errors."""
    try:
        value = value.strip()  # Ensure no trailing spaces or newlines
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO meta (name, value, last_modified)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(name) DO UPDATE SET value = excluded.value, last_modified = excluded.last_modified
            """, (name, value))
            conn.commit()
        logging.info(f"✅ DB Updated: {name} = {value[:20]}... (masked)")  # Mask for security
    except sqlite3.DatabaseError as e:
        logging.error(f"❌ Database error: {e}")


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

def string_compare(str1, str2, max_diffs=5):
    """Compares two strings index by index and outputs differences up to max_diffs."""
    
    # Generate header with first 20 characters and lengths
    header = f"compare str1:20({str1[:50]}) to str2:20({str2[:50]}) | lengths: {len(str1)} vs {len(str2)}"
    print(header)
    
    min_length = min(len(str1), len(str2))
    differences = []
    
    # Compare characters index by index
    for i in range(min_length):
        if str1[i] != str2[i]:
            differences.append(f"diff({i:03}) '{str1[i]}' != '{str2[i]}'")
            if len(differences) >= max_diffs:
                break

    # Handle cases where one string is longer
    if len(differences) < max_diffs:
        if len(str1) > len(str2):
            for i in range(min_length, len(str1)):
                differences.append(f"diff({i:03}) '{str1[i]}' != ''")
                if len(differences) >= max_diffs:
                    break
        elif len(str2) > len(str1):
            for i in range(min_length, len(str2)):
                differences.append(f"diff({i:03}) '' != '{str2[i]}'")
                if len(differences) >= max_diffs:
                    break

    # Print results
    if differences:
        for diff in differences:
            print(diff)
    else:
        print("Strings are identical")

def get_access_token(caller="unknown"):
    """Retrieves access token from the database and logs debug info."""
    access_token = get_value_from_db("access_token")

    if not access_token:
        logging.error(f"[{caller}] No access token found in the database.")
        exit(1)

    logging.info(f"[{caller}] Using access token: {access_token[:20]}... (masked)")

    # Only attempt to decode if the token has 3 segments (JWT format)
    if access_token.count('.') == 2:
        try:
            decoded_token = jwt.decode(access_token, options={"verify_signature": False})
            exp_time = decoded_token["exp"]
            current_time = int(time.time())

            if current_time >= exp_time:
                logging.info(f"[{caller}] Access token expired. Refreshing...")
                return refresh_access_token()

        except jwt.DecodeError:
            logging.warning(f"[{caller}] Token is not a valid JWT, but it may still be a valid opaque token.")

    else:
        logging.info(f"[{caller}] Token is not a JWT (may be an opaque token). Skipping decode.")

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

import json

def display_email_fields(email):
    """Displays all fields of an email, pretty-printing JSON structures and truncating output at 1000 characters."""
    logging.info("🔍 Displaying all available email fields:")

    for key, value in email.items():
        # Convert value into a readable string
        if isinstance(value, dict) or isinstance(value, list):
            value_str = json.dumps(value, indent=2)  # Pretty-print JSON structures
        else:
            value_str = str(value)  # Convert non-string values safely

        # Truncate to 1000 characters
        value_str = value_str[:100] + "..." if len(value_str) > 1000 else value_str

        logging.info(f"{key}: {value_str}")



def fetch_latest_email(access_token):
    """Retrieves the most recent email and displays all its fields."""
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(GRAPH_API_URL, headers=headers)

    if response.status_code != 200:
        logging.error(f"❌ Failed to retrieve emails: {response.json()}")
        return

    emails = response.json().get("value", [])
    if not emails:
        logging.info("📭 No emails found.")
        return

    latest_email = emails[0]  # Most recent email
    logging.info(f"✅ Latest Email Retrieved (ID: {latest_email.get('id', 'Unknown')})")

    # Call the new helper method to display all fields
    # display_email_fields(latest_email)

    email_body = latest_email["body"]["content"] if "body" in latest_email and "content" in latest_email["body"] else ""

    sender_email = latest_email["from"]["emailAddress"]["address"]
    sender_name = latest_email["from"]["emailAddress"].get("name", "")

    from_email = latest_email.get("sender", {}).get("emailAddress", {}).get("address", "")
    from_name = latest_email.get("sender", {}).get("emailAddress", {}).get("name", "")

    logging.info(f"✅ Latest Email Retrieved (ID: {latest_email['id']})")
    logging.info(f"Sender: {sender_name} <{sender_email}>")
    logging.info(f"From: {from_name} <{from_email}>")
    logging.info(f"Subject: {latest_email['subject']}")
    logging.info(f"Received At: {latest_email['receivedDateTime']}")
    logging.info(f"Body (first 100 chars): {email_body.strip()[:100]}")



# ---- Step 5: Verify Access ----
def verify_access():
    """
    Verifies access using the stored access token in the database.
    Automatically refreshes the token if expired.
    """

    logging.info("[verify-access] Calling get_access_token()...")
    access_token = get_access_token(caller="verify-access")
    logging.info("[verify-access] Retrieved access token successfully.")
    fetch_latest_email(access_token)


def collect_emails():
    """Starts a new email collection process."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    table_name = f"collection_emails_{timestamp}"

    initialize_database()
    log_to_database("collection-emails-current-table", table_name)

    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_email TEXT,
                sender_friendly_name TEXT,
                email_datetime TEXT,
                to_email TEXT,
                to_friendly_name TEXT,
                from_email TEXT,
                from_friendly_name TEXT
            )
        """)
        conn.commit()

    log_to_database(f"collection-emails-{timestamp}-complete", "false")
    process_emails(table_name, timestamp)



def collect_emails_continue():
    """Resumes email collection using the last stored delta link."""
    table_name = get_value_from_db("collection-emails-current-table")

    if not table_name:
        logging.error("No previous email collection session found. Run 'collect-emails' first.")
        return

    complete = get_value_from_db(f"{table_name}-complete")
    if complete == "true":
        logging.info("Email collection is already complete. No action needed.")
        return

    process_emails(table_name, table_name.split("_")[-1])


def fetch_emails_with_delta(url, headers):
    """Fetches emails using Microsoft Graph's delta query and returns emails + next delta link."""
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        logging.error(f"Failed to retrieve emails: {response.json()}")
        return [], None

    response_json = response.json()
    emails = response_json.get("value", [])
    
    # Prefer `@odata.deltaLink` over `@odata.nextLink`
    delta_link = response_json.get("@odata.deltaLink", response_json.get("@odata.nextLink"))

    return emails, delta_link


def process_emails(table_name, timestamp):
    """Fetches emails using Microsoft Graph's delta queries and stores metadata into the database."""
    access_token = get_access_token()
    headers = {"Authorization": f"Bearer {access_token}"}

    # Get last saved deltaLink if available
    delta_link = get_value_from_db(f"collection-emails-{timestamp}-deltalink")

    if delta_link:
        logging.info(f"Resuming email collection using stored delta link.")
        url = delta_link  # Use saved delta query URL
    else:
        logging.info(f"Starting new email collection from scratch.")
        url = f"{GRAPH_API_URL}/delta?$top=50"

    total_processed = 0
    last_processed_time = None  # Track last processed timestamp

    while url:
        emails, next_delta_link = fetch_emails_with_delta(url, headers)
        if not emails:
            logging.info("No more emails to process.")
            break

        # ✅ FIX: Unpacking correctly to avoid tuple concatenation error
        total_processed, last_processed_time = process_email_metadata_batch(emails, table_name, total_processed)

        # Store deltaLink for continuation
        if next_delta_link:
            log_to_database(f"collection-emails-{timestamp}-deltalink", next_delta_link)
            url = next_delta_link  # Use deltaLink for next iteration
        else:
            logging.info("No delta link found; reached end of traversal.")
            url = None

        log_to_database(f"collection-emails-{timestamp}-count", str(total_processed))
        logging.info(f"Processed ({total_processed}, '{last_processed_time}') emails.")

    log_to_database(f"collection-emails-{timestamp}-complete", "true")
    logging.info(f"Email collection completed. Total emails processed: {total_processed}")



def process_email_metadata_batch(emails, table_name, total_processed):
    """Processes a batch of emails, extracting full metadata and inserting into the database."""
    email_data = []
    last_processed_time = None  # Track last timestamp

    for email in emails:
        sender_email = email["from"]["emailAddress"]["address"]
        sender_name = email["from"]["emailAddress"].get("name", "")
        email_datetime = email["receivedDateTime"]  # Extract timestamp

        to_email = email.get("toRecipients", [])
        to_email = to_email[0]["emailAddress"]["address"] if to_email else ""

        to_name = email.get("toRecipients", [])
        to_name = to_name[0]["emailAddress"].get("name", "") if to_name else ""

        from_email = email.get("sender", {}).get("emailAddress", {}).get("address", "")
        from_name = email.get("sender", {}).get("emailAddress", {}).get("name", "")

        total_processed += 1
        last_processed_time = email_datetime  # Update latest timestamp

        email_data.append((sender_email, sender_name, email_datetime, to_email, to_name, from_email, from_name))

        # Debug log: Print each processed email
        logging.debug(f"{total_processed:05}, {sender_email}, {sender_name}, {email_datetime}, {to_email}, {to_name}, {from_email}, {from_name}")

    if email_data:
        update_email_table(email_data, table_name)

    return total_processed, last_processed_time  # Return updated last time


def update_email_table(email_data, table_name):
    """Inserts processed email metadata into the database."""
    try:
        with sqlite3.connect(DATABASE_FILE) as conn:
            cursor = conn.cursor()
            cursor.executemany(f"""
                INSERT INTO {table_name} (sender_email, sender_friendly_name, email_datetime, 
                                          to_email, to_friendly_name, from_email, from_friendly_name)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, email_data)
            conn.commit()
        logging.info(f"Inserted {len(email_data)} emails into {table_name}")
    except sqlite3.DatabaseError as e:
        logging.error(f"Database error while inserting emails: {e}")



def fetch_emails(headers, params):
    """Fetches emails from Microsoft Graph API."""
    response = requests.get(GRAPH_API_URL, headers=headers, params=params)
    
    if response.status_code != 200:
        logging.error(f"Failed to retrieve emails: {response.json()}")
        return []

    return response.json().get("value", [])


def process_email_batch(emails, sender_counts, total_processed):
    """Processes a batch of emails, extracting sender info and updating counts."""
    for email in emails:
        sender_email = email["from"]["emailAddress"]["address"]
        sender_name = email["from"]["emailAddress"].get("name", "")
        email_datetime = email["receivedDateTime"]
        email_subject = email["subject"]

        # Update sender count
        if sender_email in sender_counts:
            sender_counts[sender_email]["total_count"] += 1
        else:
            sender_counts[sender_email] = {"friendly_name": sender_name, "total_count": 1}

        total_processed += 1

        # Log each processed email
        logging.debug(f"{total_processed:05}, {sender_email}, {email_subject}, {email_datetime}")

    return total_processed, email_datetime  # Return new count and last email timestamp


def process_senders():
    """Processes collected emails to generate sender statistics: first email, last email, and count."""
    table_name = get_value_from_db("collection-emails-current-table")

    if not table_name:
        logging.error("No collected emails found. Run 'collect-emails' first.")
        return

    # Create the sender summary table name based on the email collection table
    timestamp = table_name.split("_")[-1]  # Extract datetime from table name
    senders_table = f"collection_senders_{timestamp}"

    # Initialize database and connection
    initialize_database()

    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()

        # Ensure the new senders table exists
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {senders_table} (
                sender_email TEXT PRIMARY KEY,
                first_email TEXT,
                last_email TEXT,
                count INTEGER
            )
        """)
        conn.commit()

        # Fetch all sender email and timestamps from the collected emails
        cursor.execute(f"SELECT sender_email, email_datetime FROM {table_name}")
        rows = cursor.fetchall()

    if not rows:
        logging.warning(f"No emails found in {table_name}. Nothing to process.")
        return

    # Process sender statistics in-memory
    sender_stats = {}

    for sender_email, email_datetime in rows:
        if sender_email not in sender_stats:
            sender_stats[sender_email] = {
                "first_email": email_datetime,
                "last_email": email_datetime,
                "count": 1
            }
        else:
            sender_stats[sender_email]["first_email"] = min(sender_stats[sender_email]["first_email"], email_datetime)
            sender_stats[sender_email]["last_email"] = max(sender_stats[sender_email]["last_email"], email_datetime)
            sender_stats[sender_email]["count"] += 1

    # Insert processed sender data back into the database
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        sender_data = [(email, data["first_email"], data["last_email"], data["count"]) for email, data in sender_stats.items()]

        cursor.executemany(f"""
            INSERT INTO {senders_table} (sender_email, first_email, last_email, count)
            VALUES (?, ?, ?, ?)
        """, sender_data)
        conn.commit()

    logging.info(f"✅ Processed {len(sender_stats)} senders and stored them in {senders_table}")
    log_to_database("collection-senders-current-table", senders_table)


# ---- Main Execution ----
def main():
    """Handles command-line arguments and executes the appropriate function."""
    parser = argparse.ArgumentParser(description="Hotmail Organizer - Authentication Manager")
    parser.add_argument("action", choices=["registration", "poll-verification", "store-access-in-db",
                                           "verify-access", 
                                           "collect-emails", "collect-emails-continue", "process-senders" ],
                        help="Select the authentication step")
    
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()
    initialize_database()  # Ensure the database is set up

    if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

    actions = {
        "registration": register_device,
        "poll-verification": poll_verification,
        "store-access-in-db": store_access_in_db,
        "verify-access": verify_access,
        "collect-emails": collect_emails,
        "collect-emails-continue": collect_emails_continue,
        "process-senders": process_senders
    }

    actions[args.action]()

if __name__ == "__main__":
    main()

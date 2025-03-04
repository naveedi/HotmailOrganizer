import argparse
import requests
import sqlite3
import logging
import time
import json
import jwt
from datetime import datetime, timedelta, timezone

# Configuration

# Configuration
DATABASE_FILE = "mail_login.db"
CLIENT_ID = "a7aa8287-afd9-4b7e-9ffb-7aa27ff62af5"  # Provided client ID
TENANT_ID = "consumers"

TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
DEVICE_CODE_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode"

GRAPH_API_URL = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"
SCOPES = "Mail.ReadWrite offline_access"
BATCH_SIZE = 100

# Logging setup
logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)

# ---- Database Setup ----
def initialize_database():
    """Creates SQLite database and ensures required tables exist with the latest schema."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()

        # Create the `meta` table for storing last processed month and other metadata
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS meta (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                last_modified DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create or update the `emails` table with new fields
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_id TEXT UNIQUE,  -- Unique email identifier for deletion
                sender_email TEXT,
                sender_friendly_name TEXT,
                email_datetime DATETIME,  -- Now properly stored as a datetime type
                to_email TEXT,
                to_friendly_name TEXT,
                from_email TEXT,
                from_friendly_name TEXT,
                email_size INTEGER,
                has_attachments BOOLEAN
            )
        """)

        # Ensure `email_id` column exists (for users with the old schema)
        cursor.execute("PRAGMA table_info(emails)")
        columns = {row[1] for row in cursor.fetchall()}
        
        if "email_id" not in columns:
            logging.info("🔄 Updating database: Adding 'email_id' column to 'emails' table.")
            cursor.execute("ALTER TABLE emails ADD COLUMN email_id TEXT UNIQUE;")
        
        if "email_datetime" in columns:
            logging.info("✅ Database already using proper schema for 'email_datetime'.")

        conn.commit()


def log_to_database(name, value):
    """Logs a value in the meta table."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO meta (name, value, last_modified)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(name) DO UPDATE SET value = excluded.value, last_modified = excluded.last_modified
        """, (name, value))
        conn.commit()

def get_value_from_db(name):
    """Retrieves a value from the meta table."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM meta WHERE name = ?", (name,))
        result = cursor.fetchone()
    return result[0] if result else None

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

# Verification of access by grabbing latest
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

def verify_access():
    """
    Verifies access using the stored access token in the database.
    Automatically refreshes the token if expired.
    """

    logging.info("[verify-access] Calling get_access_token()...")
    access_token = get_access_token(caller="verify-access")
    logging.info("[verify-access] Retrieved access token successfully.")
    fetch_latest_email(access_token)

#   Process senders from emails table
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

# ---- Step 4: Refresh ----
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
        log_to_database("access_token", tokens["access_token"])
        log_to_database("refresh_token", tokens["refresh_token"])
        return tokens["access_token"]
    else:
        logging.error(f"❌ Error refreshing token: {tokens}")
        exit(1)

def refresh_token_command():
    """Explicitly refreshes the access token and logs the result."""
    logging.info("🔄 Forcing an access token refresh...")
    new_token = refresh_access_token()
    logging.info("✅ Access token refreshed successfully and stored in the database.")

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



def fetch_emails(headers, filter_query):
    """Fetches emails from Microsoft Graph API based on the filter query, with error handling and token refresh."""
    url = f"{GRAPH_API_URL}?$top={BATCH_SIZE}&{filter_query}"
    emails = []
    retry = False  # ✅ Added to track retries

    while url:
        response = requests.get(url, headers=headers)

        if response.status_code == 401 and not retry:  # Token expired
            logging.warning("🔄 Token expired! Refreshing access token and retrying...")
            new_access_token = refresh_access_token()
            headers["Authorization"] = f"Bearer {new_access_token}"
            retry = True  # ✅ Allow one retry
            continue  # Retry the request with the new token

        if response.status_code != 200:
            logging.error(f"❌ Failed to retrieve emails: {response.text}")  # Log raw response
            return []

        try:
            response_json = response.json()
        except json.JSONDecodeError as e:
            logging.error(f"❌ JSON Decode Error: {e.msg} at position {e.pos}. Raw response: {response.text[:1000]}...")  # Log first 1000 chars of response
            return []

        emails.extend(response_json.get("value", []))
        url = response_json.get("@odata.nextLink")  # Get next page URL if available

    return emails




def process_emails_by_month(year, month):
    """Processes all emails for a given month, ensuring proper datetime filtering."""
    access_token = refresh_access_token()
    headers = {"Authorization": f"Bearer {access_token}"}
    
    # Compute first and last day of the month
    start_date = datetime(year, month, 1, tzinfo=timezone.utc)  # Ensure timezone-aware
    next_month = start_date.replace(day=28) + timedelta(days=4)  # Move to next month
    end_date = next_month.replace(day=1) - timedelta(seconds=1)  # Last second of the month

    logging.info(f"📅 Starting processing for {start_date.strftime('%Y-%m')}")

    # ✅ Fix: Ensure proper Edm.DateTimeOffset format
    start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_date_str = end_date.strftime('%Y-%m-%dT%H:%M:%SZ')

    filter_query = f"$filter=receivedDateTime ge datetime'{start_date_str}' and receivedDateTime lt datetime'{end_date_str}'"

    emails = fetch_emails(headers, filter_query)

    if emails:
        store_emails(emails)
        logging.info(f"✅ Finished processing {len(emails)} emails for {start_date.strftime('%Y-%m')}")
    else:
        logging.info(f"⚠️ No emails found for {start_date.strftime('%Y-%m')}")

    # Mark month as processed
    log_to_database("last_processed_month", f"{year}-{month:02d}")


def store_emails(emails):
    """Stores processed email data into the database with full error handling for missing fields."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        data = []
        
        for email in emails:
            try:
                # Store the stable email ID so we can use it later for deletion if required
                email_id = email.get("id", "")  # Store the email ID

                # Handle missing sender details safely
                sender = email.get("from", {}).get("emailAddress", {})
                sender_email = sender.get("address", "") if isinstance(sender, dict) else ""
                sender_name = sender.get("name", "") if isinstance(sender, dict) else ""

                # Ensure email has a valid received date
                email_datetime = email.get("receivedDateTime", "")
                if email_datetime:
                    email_datetime = datetime.strptime(email_datetime, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")

                # Handle missing or empty toRecipients
                to_recipients = email.get("toRecipients", [])
                to_email = to_recipients[0]["emailAddress"]["address"] if to_recipients and "emailAddress" in to_recipients[0] else ""
                to_name = to_recipients[0]["emailAddress"]["name"] if to_recipients and "emailAddress" in to_recipients[0] else ""

                # Handle missing sender details (sometimes "from" and "sender" may differ)
                sender_data = email.get("sender", {}).get("emailAddress", {})
                from_email = sender_data.get("address", "") if isinstance(sender_data, dict) else ""
                from_name = sender_data.get("name", "") if isinstance(sender_data, dict) else ""

                # Ensure email size is numeric
                email_size = email.get("size", 0)
                email_size = int(email_size) if isinstance(email_size, (int, float)) else 0

                # Ensure attachments are properly detected
                has_attachments = email.get("hasAttachments", False)
                has_attachments = bool(has_attachments) if isinstance(has_attachments, bool) else False

                # Add to batch
                data.append((sender_email, sender_name, email_datetime, to_email, to_name, from_email, from_name, email_size, has_attachments))

            except Exception as e:
                logging.error(f"❌ Error processing email ID {email.get('id', 'UNKNOWN')}: {e}")
                continue  # Skip problematic emails without stopping execution

        # Insert into database in batch mode
        if data:
            try:
                cursor.executemany("""
                    INSERT INTO emails (
                        email_id, sender_email, sender_friendly_name, email_datetime, 
                        to_email, to_friendly_name, from_email, from_friendly_name, 
                        email_size, has_attachments
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, data)

                conn.commit()
                logging.info(f"✅ Inserted {len(data)} emails into the database.")
            except sqlite3.DatabaseError as db_error:
                logging.error(f"❌ Database error while inserting emails: {db_error}")


def process_emails():
    """Processes emails month by month, starting from the last processed month and working backwards."""
    current_date = datetime.now(timezone.utc)
    last_processed = get_value_from_db("last_processed_month")

    # Define the minimum date we will process (inclusive)
    min_date = datetime(2013, 1, 1, tzinfo=timezone.utc)

    if last_processed:
        last_year, last_month = map(int, last_processed.split("-"))
        start_date = datetime(last_year, last_month, 1, tzinfo=timezone.utc) - timedelta(days=1)
    else:
        start_date = current_date.replace(day=1, tzinfo=timezone.utc) - timedelta(days=1)  # Previous month

    while start_date >= min_date:  # ✅ Stop when reaching 2013-01
        process_emails_by_month(start_date.year, start_date.month)
        start_date = start_date.replace(day=1) - timedelta(days=1)  # Move to previous month

    logging.info("🎉 Completed processing all emails up to January 2013.")



# ---- Main Execution ----
def main():
    """Handles command-line arguments and executes the appropriate function."""
    parser = argparse.ArgumentParser(description="Hotmail Organizer - Authentication Manager")
    parser.add_argument("action", choices=["registration", 
                                           "poll-verification", 
                                           "verify-access", 
                                           "process-senders", 
                                           "refresh-token",
                                           "process-emails"
                                         ],
                        help="Select the authentication step")
    
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()
    initialize_database()  # Ensure the database is set up

    if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

    actions = {
        "registration": register_device,
        "poll-verification": poll_verification,
        "verify-access": verify_access,
        "process-senders": process_senders,
        "refresh-token": refresh_token_command,  
        "process-emails": process_emails,
    }

    actions[args.action]()

if __name__ == "__main__":
    main()
# Hotmail Organizer

A Python tool for authenticating, collecting, and managing emails from Hotmail using the Microsoft Graph API.

## Features
- OAuth2 authentication using Device Code Flow
- Fetches senders' email addresses and stores them in a database
- Supports resuming interrupted data collection
- Logs progress and errors

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/naveedi/HotmailOrganizer.git
   cd HotmailOrganizer
   ```

## Dependencies
   ```bash
   gpip install requests sqlite3 logging argparse
   ```
## Usage 
### Authenticate
```bash
python mail_login.py registration
python mail_login.py poll-verification
```

### Process Emails
```bash
python mail_login.py collect-senders
python mail_login.py collect-senders-continue
```
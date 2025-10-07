import hashlib
import cloudscraper
import random
import string
import time
import json
import os
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64

CONTENT_FILE = "content.json"

def get_env_var(name: str, required: bool = True) -> str:
    """Get environment variable with optional requirement check"""
    value = os.environ.get(name)
    if required and not value:
        raise ValueError(f"{name} environment variable not set")
    return value

def get_encryption_key():
    """Get encryption key from environment variable"""
    key = get_env_var('ENCRYPTION_KEY')
    # Ensure key is 32 bytes for AES-256
    return hashlib.sha256(key.encode()).digest()

def encrypt_data(data: dict) -> str:
    """Encrypt data using AES-256-CBC"""
    key = get_encryption_key()
    iv = os.urandom(16)
    
    # Convert dict to JSON string
    json_str = json.dumps(data)
    
    # Pad the data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(json_str.encode()) + padder.finalize()
    
    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    
    # Combine IV and encrypted data, then base64 encode
    combined = iv + encrypted
    return base64.b64encode(combined).decode('utf-8')

def decrypt_data(encrypted_str: str) -> dict:
    """Decrypt data using AES-256-CBC"""
    key = get_encryption_key()
    
    # Base64 decode
    combined = base64.b64decode(encrypted_str)
    
    # Extract IV and encrypted data
    iv = combined[:16]
    encrypted = combined[16:]
    
    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted) + decryptor.finalize()
    
    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    # Convert JSON string back to dict
    return json.loads(data.decode())

def load_stored_data() -> dict:
    """Load and decrypt stored data from content.json"""
    if not os.path.exists(CONTENT_FILE):
        return {}
    
    try:
        with open(CONTENT_FILE, 'r') as f:
            content = f.read().strip()
            if not content:
                return {}
            encrypted_data = json.load(open(CONTENT_FILE, 'r'))
            return decrypt_data(encrypted_data['data'])
    except (json.JSONDecodeError, KeyError, Exception) as e:
        print(f"Error loading stored data: {e}")
        return {}

def save_stored_data(data: dict):
    """Encrypt and save data to content.json"""
    encrypted = encrypt_data(data)
    with open(CONTENT_FILE, 'w') as f:
        json.dump({'data': encrypted}, f)

def get_bangkok_time_str():
    now = datetime.utcnow() + timedelta(hours=7)
    return now.strftime("%Y/%m/%d %H:%M")

def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_session_token():
    fingerprint_string = "::".join([
        random_string(12),
        random_string(5),
        f"{random.randint(800, 3840)}x{random.randint(600, 2160)}",
        str(random.randint(1, 30)),
        random.choice([
            "Asia/Bangkok", "Asia/Singapore", "Europe/London",
            "America/New_York", "Asia/Hong_Kong", "Asia/Seoul",
            "Asia/Shanghai", "Asia/Tokyo"
        ]),
        random_string(10),
        random_string(10),
        random.choice(["en-US", "th-TH", "fr-FR", "en-UK", "jp-JP", "ch-ZN"]),
        random_string(10),
        random_string(10),
    ])
    sha256 = hashlib.sha256()
    sha256.update(fingerprint_string.encode('utf-8'))
    return sha256.hexdigest()

def submit_form(scraper, url, sessiontoken):
    if not url:
        raise ValueError("URL cannot be empty.")
    if not sessiontoken:
        sessiontoken = generate_session_token()
    data = {'refcode': sessiontoken}
    response = scraper.post(url, data=data, allow_redirects=False)
    print("Status code:", response.status_code)
    if response.status_code in (301, 302, 303, 307, 308):
        redirect_url = response.headers.get('Location')
        return redirect_url
    else:
        print("No redirect URL found. Response content:")
        print(response.text)
        return None

def extract_name_from_url(url: str) -> str:
    if url.endswith("/"):
        url = url[:-1]
    last_part = url.split("/")[-1]
    name_with_spaces = last_part.replace("-", " ")
    return " ".join(word.capitalize() for word in name_with_spaces.split())

def main():
    # Get configuration from environment variables
    url = get_env_var('ENDPOINT_URL')
    ntfy_endpoint = get_env_var('NTFY_ENDPOINT')
    
    scraper = cloudscraper.create_scraper()

    # Fetch HTML using cloudscraper
    response = scraper.get(url)
    response.raise_for_status()
    html = response.text

    sessionToken = generate_session_token()

    try:
        extracted_url = html.split('<div class="su-button-center"><a href="')[1].split('"')[0]
    except IndexError:
        raise RuntimeError("Expected content not found.")

    # Load stored data from encrypted file
    stored = load_stored_data()

    stored_url = stored.get("latestUrl")
    stored_canvaJoin = stored.get("latestJoin", None)
    teamName = stored.get("teamName", None)
    timestamp = get_bangkok_time_str()

    if stored_url == extracted_url:
        message = (
            f"[{timestamp} BKK Time] 🔔 No change detected on the monitored page.\n"
            f"Current Team: {teamName or 'Undefined'}"
        )
        scraper.post(
            ntfy_endpoint,
            data=message.encode("utf-8"),
            headers={
                "Title": "No Change Detected",
                "Tags": "",
                "priority": "1",
                "Actions": f"view, {'Join ' + (teamName or 'Undefined') + ' team' if stored_canvaJoin else 'check out current link!'}, {stored_canvaJoin if stored_canvaJoin else extracted_url};"
            }
        )
    else:
        message = f"[{timestamp} BKK Time] 🚨 New link detected!\n"
        joinLink = submit_form(scraper, extracted_url, sessionToken)
        teamName = extract_name_from_url(extracted_url)
        message += f"Team Name: {teamName}\n"

        if joinLink:
            message += f"Join link: {joinLink or 'None'}\nCheck it out!!"
        else:
            message += "No join link found."

        timestamp_unix = int(time.time())
        
        # Save encrypted data to file
        new_data = {
            "latestUrl": extracted_url,
            "latestJoin": joinLink,
            "teamName": teamName,
            "lastUpdate": timestamp_unix
        }
        save_stored_data(new_data)
        print("Data saved successfully")

        scraper.post(
            ntfy_endpoint,
            data=message.encode("utf-8"),
            headers={
                "Title": "New Link Detected",
                "Tags": "link,alert",
                "priority": "5",
                "Actions": f"view, {'Join ' + (teamName or 'Undefined') + ' team' if joinLink else 'check out new link!'}, {joinLink if joinLink else extracted_url};"
            }
        )

if __name__ == "__main__":
    main()

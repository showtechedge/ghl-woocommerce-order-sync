import os

def create_file(filename, content):
    if filename == ".env" and os.path.exists(filename):
        print(f"⚠️  Skipped: {filename} exists (Preserving secrets).")
        return
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content.strip())
        print(f"✅ Generated: {filename}")
    except Exception as e:
        print(f"❌ Error creating {filename}: {e}")

def main():
    # --- 1. REQUIREMENTS ---
    reqs = """
flask
requests
python-dotenv
"""

    # --- 2. .ENV ---
    env_content = """
# SERVER CONFIG
PORT=5000

# WOOCOMMERCE SETTINGS
# Get this from WooCommerce -> Settings -> Advanced -> Webhooks
WOO_WEBHOOK_SECRET=my_super_secret_woo_key

# GHL SETTINGS
GHL_API_KEY=your_ghl_api_key_here
GHL_PIPELINE_ID=your_pipeline_id_here
"""

    # --- 3. MAIN.PY (The Integration Engine) ---
    main_code = """
import os
import sys
import hmac
import hashlib
import base64
import logging
import json
import requests
from flask import Flask, request, jsonify, abort
from dotenv import load_dotenv

# --- WINDOWS CONSOLE FIX ---
if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

# --- CONFIG ---
load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("WooSync")

app = Flask(__name__)

WOO_SECRET = os.getenv("WOO_WEBHOOK_SECRET")
GHL_API_KEY = os.getenv("GHL_API_KEY")

# --- UTILS: SECURITY ---
def verify_woo_signature(request_data, signature_header):
    \"\"\"
    Verifies that the request actually came from WooCommerce using HMAC-SHA256.
    This prevents hackers from faking orders.
    \"\"\"
    if not WOO_SECRET:
        return True # Dev mode (Skip if no secret set)
        
    if not signature_header:
        return False

    # Calculate expected signature
    digest = hmac.new(
        WOO_SECRET.encode('utf-8'),
        request_data,
        hashlib.sha256
    ).digest()
    
    calculated_signature = base64.b64encode(digest).decode('utf-8')
    
    # Compare (Safe compare to avoid timing attacks)
    return hmac.compare_digest(calculated_signature, signature_header)

# --- ROUTES ---
@app.route('/woo-order', methods=['POST'])
def handle_woo_order():
    # 1. Security Check (HMAC)
    signature = request.headers.get("X-WC-Webhook-Signature")
    if not verify_woo_signature(request.get_data(), signature):
        logger.warning("⛔ Security Alert: Invalid Signature detected!")
        abort(401, description="Invalid Signature")

    # 2. Parse Payload
    data = request.json
    order_id = data.get("id")
    status = data.get("status")
    total = data.get("total")
    currency = data.get("currency")
    
    # Extract Customer Info
    billing = data.get("billing", {})
    email = billing.get("email")
    first_name = billing.get("first_name")
    phone = billing.get("phone")

    logger.info(f"📦 Received Order #{order_id} from {first_name} (${total} {currency})")

    # 3. Filter Logic (Only process 'processing' or 'completed' orders)
    if status not in ['processing', 'completed']:
        logger.info(f"Skipping order #{order_id} (Status: {status})")
        return jsonify({"status": "ignored"}), 200

    # 4. Sync to GHL (Mocked for Portfolio)
    # In production, we would POST to https://rest.gohighlevel.com/v1/opportunities/
    
    ghl_payload = {
        "title": f"Order #{order_id} - {first_name}",
        "status": "won",
        "monetaryValue": total,
        "contact": {
            "email": email,
            "phone": phone,
            "name": f"{first_name} {billing.get('last_name')}"
        }
    }
    
    logger.info(f"🚀 Syncing to GHL Opportunity: {json.dumps(ghl_payload, indent=2)}")
    
    # Simulating GHL Response
    return jsonify({"status": "synced", "ghl_id": "mock_opp_123"}), 200

if __name__ == '__main__':
    print("🛒 Woo-GHL Sync Engine Running...")
    app.run(port=5000)
"""

    # --- 4. MOCK TRIGGER (Simulates WooCommerce) ---
    mock_code = """
import requests
import json
import hmac
import hashlib
import base64
import time

# CONFIG
URL = "http://127.0.0.1:5000/woo-order"
SECRET = "my_super_secret_woo_key" # Must match .env

def generate_signature(payload, secret):
    \"\"\"Generates a valid WooCommerce HMAC signature for the payload.\"\"\"
    digest = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).digest()
    return base64.b64encode(digest).decode('utf-8')

def send_fake_order(order_id, total, status="processing"):
    # 1. Create Fake Order JSON
    data = {
        "id": order_id,
        "status": status,
        "total": str(total),
        "currency": "USD",
        "billing": {
            "first_name": "Showtech",
            "last_name": "CEO",
            "email": "ceo@showtechedge.com",
            "phone": "+2348000000000"
        }
    }
    json_data = json.dumps(data)

    # 2. Sign it (So the server trusts us)
    signature = generate_signature(json_data, SECRET)
    
    # 3. Send
    headers = {
        "Content-Type": "application/json",
        "X-WC-Webhook-Signature": signature
    }
    
    print(f"📤 Sending Order #{order_id} (${total})...")
    try:
        resp = requests.post(URL, data=json_data, headers=headers)
        print(f"Result: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"Error: {e}")
    print("-" * 30)

if __name__ == "__main__":
    print("🛒 Simulating WooCommerce Webhooks...")
    
    # Valid Order
    send_fake_order(1001, 150.00, "processing")
    
    # Invalid Status (Should be ignored)
    send_fake_order(1002, 0.00, "cancelled")
    
    # HACKER TEST (Wrong Signature)
    print("🕵️  Hacker Simulation (Invalid Signature)...")
    requests.post(URL, json={"id": 999}, headers={"X-WC-Webhook-Signature": "fake_sig"})
    print("Check server logs (Should say 401 Unauthorized)")
"""

    # --- 5. README ---
    readme = """# 🛒 WooCommerce to GHL Sync
### Built by Showtechedge

A specialized middleware that syncs WooCommerce orders to GoHighLevel Opportunities in real-time.

### 🛡️ Enterprise Security
* **HMAC Verification:** Manually calculates SHA256 signatures to verify that incoming webhooks are genuinely from WooCommerce, rejecting any spoofed data.
* **Status Filtering:** Only syncs 'Processing' or 'Completed' orders to avoid cluttering the pipeline with cancelled/failed carts.

### ⚙️ Setup
1. **Configure .env:**
   ```ini
   WOO_WEBHOOK_SECRET=your_woo_secret
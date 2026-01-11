import os
import sys
import hmac
import hashlib
import base64
import logging
import json
import requests
from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv
from cachetools import TTLCache

# --- WINDOWS CONSOLE FIX ---
if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

# --- CONFIG & SETUP ---
load_dotenv()

# Sanitized Logger (No PII)
class PiiFilter(logging.Filter):
    def filter(self, record):
        # We handle PII masking manually in the log messages
        return True

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("sync.log", encoding='utf-8')
    ]
)
logger = logging.getLogger("WooSync")

app = Flask(__name__)

# Secrets
WOO_SECRET = os.getenv("WOO_WEBHOOK_SECRET")
GHL_API_KEY = os.getenv("GHL_API_KEY")

# 1. RATE LIMITER (DDoS Protection)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "100 per hour"],
    storage_uri="memory://"
)

# 2. IDEMPOTENCY CACHE (Prevent Duplicates)
# Stores Order IDs for 24 hours. If Woo sends the same webhook twice, we ignore the second.
processed_orders = TTLCache(maxsize=10000, ttl=86400)

# --- UTILS ---

def mask_pii(text):
    """Masks emails/phones for logs (GDPR Compliance)."""
    if not text: return "N/A"
    if "@" in text: # Email
        user, domain = text.split("@")
        return f"{user[:2]}***@{domain}"
    if len(text) > 4: # Phone
        return f"***-{text[-4:]}"
    return text

def verify_woo_signature(request_data, signature_header):
    """HMAC-SHA256 Signature Verification."""
    if not WOO_SECRET:
        return True # Dev mode
    if not signature_header:
        return False
    
    digest = hmac.new(
        WOO_SECRET.encode('utf-8'),
        request_data,
        hashlib.sha256
    ).digest()
    calculated_sig = base64.b64encode(digest).decode('utf-8')
    return hmac.compare_digest(calculated_sig, signature_header)

def get_retry_session():
    """Tenacious API Client with Exponential Backoff."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1, # Wait 1s, 2s, 4s...
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def sync_to_ghl(payload):
    """
    Mock function to send data to GHL. 
    In production, this would use 'get_retry_session().post(...)'.
    """
    # Logic: Create Contact -> Create Opportunity
    # We mock this for the portfolio demonstration
    return {"status": "success", "id": "ghl_12345"}

# --- ROUTES ---

@app.route('/woo-order', methods=['POST'])
@limiter.limit("20 per minute") # Specific limit for this heavy endpoint
def handle_woo_order():
    # A. Security Check (HMAC)
    signature = request.headers.get("X-WC-Webhook-Signature")
    if not verify_woo_signature(request.get_data(), signature):
        logger.warning(f"⛔ Security Alert: Invalid Signature from {request.remote_addr}")
        abort(401, description="Invalid Signature")

    # B. Parse & Validate
    try:
        data = request.json
        if not data:
            return jsonify({"status": "ignored", "reason": "empty"}), 200
    except Exception:
        logger.error("Failed to parse JSON payload")
        return jsonify({"error": "Bad JSON"}), 400

    order_id = data.get("id")
    status = data.get("status")
    
    # C. Idempotency Check (The "Duplicate Killer")
    if order_id in processed_orders:
        logger.info(f"♻️  Skipping Duplicate Order #{order_id} (Already Processed)")
        return jsonify({"status": "skipped", "reason": "duplicate"}), 200

    # D. Business Logic Filtering
    if status not in ['processing', 'completed']:
        logger.info(f"Skipping Order #{order_id} (Status: {status})")
        return jsonify({"status": "ignored"}), 200

    # Extract & Mask PII
    billing = data.get("billing", {})
    email = billing.get("email")
    phone = billing.get("phone")
    total = data.get("total")
    
    # LOGGING: Note how we do NOT log the raw email/phone
    logger.info(f"📦 Processing Order #{order_id} | Customer: {mask_pii(email)} | Value: ${total}")

    # E. Execution (Sync)
    try:
        # 1. Map Data
        ghl_payload = {
            "title": f"Order #{order_id}",
            "value": total,
            "status": "won",
            "email": email, # Send real data to API
            "phone": phone
        }
        
        # 2. Send to GHL (Using Retry Logic)
        # response = get_retry_session().post(...) # Real implementation
        result = sync_to_ghl(ghl_payload) # Mock implementation
        
        # 3. Mark as Processed (Cache it)
        processed_orders[order_id] = "synced"
        
        logger.info(f"✅ Order #{order_id} Synced Successfully.")
        return jsonify({"status": "synced", "ghl_id": result['id']}), 200

    except Exception as e:
        logger.error(f"❌ Sync Failed for Order #{order_id}: {e}")
        # In a real app, we would push this to a Dead Letter Queue (DLQ) here
        return jsonify({"error": "internal_error"}), 500

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    print(f"🛒 Enterprise Woo-Sync Engine Running on port {port}...")
    app.run(port=port)
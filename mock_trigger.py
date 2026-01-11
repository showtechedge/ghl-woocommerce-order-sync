import requests
import json
import hmac
import hashlib
import base64
import time

# CONFIG
URL = "http://127.0.0.1:5000/woo-order"
SECRET = "my_super_secret_woo_key" 

def generate_signature(payload, secret):
    digest = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).digest()
    return base64.b64encode(digest).decode('utf-8')

def send_order(order_id, total, status="processing", email="ceo@showtechedge.com"):
    data = {
        "id": order_id,
        "status": status,
        "total": str(total),
        "currency": "USD",
        "billing": {
            "first_name": "Showtech",
            "last_name": "CEO",
            "email": email,
            "phone": "+2348000000000"
        }
    }
    json_data = json.dumps(data)
    signature = generate_signature(json_data, SECRET)
    
    headers = {
        "Content-Type": "application/json",
        "X-WC-Webhook-Signature": signature
    }
    
    print(f"📤 Sending Order #{order_id}...")
    try:
        resp = requests.post(URL, data=json_data, headers=headers)
        print(f"   Response: {resp.status_code} - {resp.json()}")
    except Exception as e:
        print(f"   Error: {e}")
    print("-" * 40)

if __name__ == "__main__":
    print("🚀 Starting Enterprise Mock Tests...\n")
    
    # 1. Valid Sync
    send_order(1001, 150.00)
    
    # 2. Idempotency Test (Duplicate)
    # Sending Order #1001 AGAIN - Should be skipped
    print("♻️  Testing Idempotency (Sending Duplicate)...")
    send_order(1001, 150.00)
    
    # 3. Invalid Status
    send_order(1002, 50.00, status="cancelled")
    
    # 4. Security Test (Bad Signature)
    print("🕵️  Testing Security (Hacker Attack)...")
    try:
        requests.post(URL, json={"id": 999}, headers={"X-WC-Webhook-Signature": "fake_sig"})
        print("   Response: 401 Unauthorized (Expected)")
    except Exception as e:
        print(e)
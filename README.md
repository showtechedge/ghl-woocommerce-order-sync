# 🛒 WooCommerce <-> GHL Sync (Enterprise Edition)
### Built by Showtechedge

A production-grade middleware that bridges WooCommerce sales data with GoHighLevel (GHL). It features military-grade security and data integrity checks.

### 🌟 Senior-Level Features
* **🔐 Security First:** Verifies **HMAC-SHA256 Signatures** to reject hacker attempts/spoofed data.
* **♻️ Idempotency:** Uses an in-memory `TTLCache` to instantly reject duplicate webhooks (preventing duplicate "Won" deals).
* **🕵️ Privacy (GDPR):** Automatically masks PII (Emails/Phones) in server logs.
* **🌊 Tenacity:** Rate Limiting (1000 req/day) and Smart Retries for API stability.

---

## ⚙️ Configuration (.env)
Secure your API keys and secrets here. Do not commit this file to GitHub.

```ini
# Server Port
PORT=5000

# WOOCOMMERCE SETTINGS
# Get this from WooCommerce -> Settings -> Advanced -> Webhooks
WOO_WEBHOOK_SECRET=my_super_secret_woo_key

# GHL SETTINGS
GHL_API_KEY=your_ghl_api_key_here
```

---

## 📡 API Reference

### 1. Receive Order Webhook
**Endpoint:** `/woo-order`
**Method:** `POST`
**Headers:** * `X-WC-Webhook-Signature`: (Required) HMAC-SHA256 hash of the payload.

#### Request Body
Accepts standard WooCommerce Order JSON.

```json
{
  "id": 1001,
  "status": "processing",
  "total": "150.00",
  "currency": "USD",
  "billing": {
    "first_name": "John",
    "last_name": "Doe",
    "email": "john@example.com",
    "phone": "+1234567890"
  }
}
```

### 🔄 Scenarios & Responses

#### Scenario A: Valid Order
Order is new, signature is valid, and status is 'processing'.

```json
{
  "status": "synced",
  "ghl_id": "ghl_12345"
}
```

#### Scenario B: Duplicate (Idempotency)
WooCommerce sends the same webhook twice by mistake.

```json
{
  "status": "skipped",
  "reason": "duplicate"
}
```
*Log Output:* `♻️ Skipping Duplicate Order #1001`

#### Scenario C: Hacker Attack
Request signature does not match the secret key.

```json
{
  "error": "Invalid Signature"
}
```
*Status Code:* `401 Unauthorized`


---

## 🛠 Local Installation

1. **Clone the repo**
   ```bash
   git clone [https://github.com/showtechedge/ghl-woocommerce-order-sync.git](https://github.com/showtechedge/ghl-woocommerce-order-sync.git)
   ```

2. **Install Requirements**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run Server**
   ```bash
   python main.py
   ```

4. **Run Tests (Simulations)**
   ```bash
   python mock_trigger.py
   ```

---

**© 2026 Showtechedge.**

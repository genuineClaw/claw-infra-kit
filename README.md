# OpenClaw GitHub Webhook Infrastructure

Webhook receiver that triggers OpenClaw agent when `@genuineClaw` is mentioned by `pkuGenuine`.

## Quick Start

### 1. Configure

Edit `config.json`:

```json
{
  "webhook_secret": "YOUR_SECURE_RANDOM_SECRET",
  "openclaw_endpoint": "http://localhost:3000",
  "openclaw_session": "main",
  "authorized_user": "pkuGenuine",
  "assistant_account": "genuineClaw",
  "watched_repos": ["genuineClaw/lspyc", "genuineClaw/CodeRetrX"],
  "github_ips_only": true,
  "port": 8080
}
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run

```bash
python webhook_server.py
```

Server runs on `http://0.0.0.0:8080`

### 4. Expose via ngrok (for testing)

```bash
ngrok http 8080
# Use the HTTPS URL for GitHub webhook
```

### 5. Configure GitHub Webhook

```bash
gh api repos/genuineClaw/lspyc/hooks \
  -f content_type=json \
  -f url="https://YOUR_NGROK_URL/webhook" \
  -f secret="YOUR_WEBHOOK_SECRET" \
  -f events='["issues","issue_comment","pull_request"]'
```

## Production Deployment

### Using Systemd

```bash
# Copy files to /opt
sudo mkdir -p /opt/claw-infra-kit
sudo cp webhook_server.py config.json requirements.txt /opt/claw-infra-kit/

# Install service
sudo cp claw-webhook.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable claw-webhook
sudo systemctl start claw-webhook
```

### Check Status

```bash
sudo systemctl status claw-webhook
journalctl -u claw-webhook -f
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/webhook` | POST | GitHub webhook receiver |
| `/health` | GET | Health check |
| `/` | GET | Service info |

## Security Features

- ✅ HMAC-SHA256 signature verification
- ✅ IP allowlist (GitHub IP ranges only)
- ✅ Authorized user check (only `pkuGenuine`)
- ✅ Mention verification (only `@genuineClaw`)
- ✅ Repository allowlist

## Flow

```
GitHub Issue/PR Comment
        │
        ▼
┌──────────────────┐
│ Webhook Receiver │ ← Verifies signature + IP + user
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Filter Check    │ ← @genuineClaw from pkuGenuine?
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Trigger OpenClaw │ ← POST /api/sessions/main/send
└──────────────────┘
```
# Claw Infra Kit

Infrastructure tools for OpenClaw agent interaction. Multi-package monorepo managed by `uv`.

## Packages

| Package | Description |
|---------|-------------|
| [`packages/webhook`](packages/webhook/) | GitHub webhook receiver that spawns isolated agent sessions |

## Quick Start

### 1. Install uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Configure

Edit `config.toml` at repo root:

```toml
[webhook]
secret = "YOUR_SECURE_RANDOM_SECRET"
port = 8080
github_ips_only = true

[openclaw]
endpoint = "http://localhost:3000"
agent_id = "coder"
runtime = "subagent"
mode = "run"

[github]
authorized_user = "pkuGenuine"
assistant_account = "genuineClaw"
watched_repos = [
    "genuineClaw/lspyc",
    "genuineClaw/CodeRetrX",
]
```

### 3. Run

```bash
# From repo root
uv run --directory packages/webhook python -m webhook.server

# Or directly
uv run --directory packages/webhook webhook.server:main
```

Server runs on `http://0.0.0.0:8080`

### 4. Expose via HTTPS

For testing without a domain:

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
sudo cp -r . /opt/claw-infra-kit/

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

## How It Works

```
GitHub Issue/PR Comment (@genuineClaw from pkuGenuine)
                    │
                    ▼
         ┌──────────────────┐
         │  Webhook Server  │ ← Verifies signature + IP + user
         └────────┬─────────┘
                  │
                  ▼
         ┌──────────────────┐
         │  sessions_spawn  │ ← Spawns isolated "coder" agent
         └────────┬─────────┘
                  │
                  ▼
         ┌──────────────────┐
         │  Agent Session   │ ← Handles issue, posts via gh CLI
         └──────────────────┘
```

## Security

- ✅ HMAC-SHA256 signature verification
- ✅ GitHub IP allowlist
- ✅ Authorized user check (only `pkuGenuine`)
- ✅ Mention verification (only `@genuineClaw`)
- ✅ Repository allowlist

## Development

### Project Structure

```
claw-infra-kit/
├── pyproject.toml          # Root workspace config
├── config.toml             # Configuration
├── packages/
│   └── webhook/            # Webhook receiver package
│       ├── pyproject.toml
│       └── src/webhook/
│           ├── __init__.py
│           └── server.py
└── README.md
```

### Adding a New Package

```bash
mkdir -p packages/new-package/src/new_package
# Create pyproject.toml and source files
# Add to [tool.uv.workspace] members in root pyproject.toml
```
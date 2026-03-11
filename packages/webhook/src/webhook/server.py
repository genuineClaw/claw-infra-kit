#!/usr/bin/env python3
"""
GitHub Webhook Receiver for OpenClaw Agent

Receives GitHub webhooks, filters for @genuineClaw mentions from authorized user,
and spawns isolated OpenClaw sessions to handle each issue/PR.
"""

import json
import hmac
import hashlib
import ipaddress
import re
import tomllib
import logging
import urllib.parse
import subprocess
import asyncio
from pathlib import Path
from datetime import datetime

import uvicorn
from fastapi import FastAPI, Request, HTTPException

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# Find config file (check multiple locations)
# Path from server.py: .../packages/webhook/src/webhook/server.py
# Need 5 parents to get to repo root
CONFIG_PATHS = [
    Path(__file__).parent.parent.parent.parent.parent / "config.toml",  # repo root
    Path(__file__).parent.parent.parent.parent / "config.toml",  # packages/
    Path("/etc/claw-infra-kit/config.toml"),  # system config
]


def load_config() -> dict:
    """Load configuration from TOML file."""
    for path in CONFIG_PATHS:
        logger.debug(f"Checking config path: {path}")
        if path.exists():
            logger.info(f"Loading config from: {path}")
            with open(path, "rb") as f:
                return tomllib.load(f)
    logger.warning(f"No config found. Searched: {CONFIG_PATHS}")
    return {}


config = load_config()
DEBUG = config.get("webhook", {}).get("debug", False)

# GitHub's IP ranges for webhook delivery
# https://api.github.com/meta
GITHUB_IP_RANGES = [
    "192.30.252.0/22",
    "185.199.108.0/22",
    "140.82.112.0/20",
    "143.55.64.0/20",
]

app = FastAPI(title="OpenClaw GitHub Webhook")


def verify_github_ip(client_ip: str) -> bool:
    """Check if request comes from GitHub's IP range."""
    github_ips_only = config.get("webhook", {}).get("github_ips_only", True)
    logger.debug(f"IP check enabled: {github_ips_only}, client IP: {client_ip}")

    if not github_ips_only:
        logger.info("IP verification disabled, allowing all IPs")
        return True

    try:
        client_addr = ipaddress.ip_address(client_ip)
        for cidr in GITHUB_IP_RANGES:
            if client_addr in ipaddress.ip_network(cidr):
                logger.debug(f"IP {client_ip} matches GitHub range {cidr}")
                return True
    except ValueError as e:
        logger.warning(f"Invalid IP address '{client_ip}': {e}")
        return False

    logger.warning(f"IP {client_ip} not in GitHub ranges")
    return False


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook signature using HMAC-SHA256."""
    logger.debug(f"Verifying signature, got: {signature[:20] if signature else 'None'}...")

    if not signature or not signature.startswith("sha256="):
        logger.warning(f"Invalid signature format: {signature}")
        return False

    expected = signature[7:]  # Remove "sha256=" prefix

    computed = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    if DEBUG:
        logger.debug(f"Computed signature: {computed}")
        logger.debug(f"Expected signature: {expected}")

    result = hmac.compare_digest(computed, expected)
    logger.debug(f"Signature verification result: {result}")
    return result


def should_trigger(payload: dict, event_type: str) -> tuple[bool, str | dict]:
    """
    Determine if this webhook should trigger the agent.
    Returns (should_trigger, info_dict_or_reason_string).
    """
    github_config = config.get("github", {})
    authorized_user = github_config.get("authorized_user", "pkuGenuine")
    assistant_account = github_config.get("assistant_account", "genuineClaw")
    watched_repos = github_config.get("watched_repos", [])

    logger.debug(f"Checking trigger: event_type={event_type}")
    logger.debug(f"Config: authorized_user={authorized_user}, assistant={assistant_account}")
    logger.debug(f"Watched repos: {watched_repos}")

    # Check action is "created" or "opened" (not edit/delete)
    action = payload.get("action", "")
    logger.debug(f"Action: {action}")
    if action not in ("created", "opened"):
        return False, f"Action '{action}' ignored (only 'created'/'opened' trigger)"

    # Check repository is in watched list
    repo_full_name = payload.get("repository", {}).get("full_name", "")
    logger.debug(f"Repository: {repo_full_name}")
    if repo_full_name not in watched_repos:
        return False, f"Repo '{repo_full_name}' not in watched repos"

    # Check sender is authorized
    sender = payload.get("sender", {}).get("login", "")
    logger.debug(f"Sender: {sender}")
    if sender != authorized_user:
        return False, f"Sender '{sender}' not authorized (expected '{authorized_user}')"

    # Check for @mention based on event type
    issue_url = None
    issue_title = None
    issue_number = None
    mention_text = None

    if event_type == "issues":
        issue_body = payload.get("issue", {}).get("body", "") or ""
        logger.debug(f"Issue body: {issue_body[:200]}...")
        if f"@{assistant_account}" in issue_body:
            mention_text = issue_body
            issue_url = payload.get("issue", {}).get("html_url", "")
            issue_title = payload.get("issue", {}).get("title", "")
            issue_number = payload.get("issue", {}).get("number")

    elif event_type == "issue_comment":
        comment_body = payload.get("comment", {}).get("body", "") or ""
        logger.debug(f"Comment body: {comment_body[:200]}...")
        if f"@{assistant_account}" in comment_body:
            mention_text = comment_body
            issue_url = payload.get("issue", {}).get("html_url", "")
            issue_title = payload.get("issue", {}).get("title", "")
            issue_number = payload.get("issue", {}).get("number")

    elif event_type == "pull_request":
        pr_body = payload.get("pull_request", {}).get("body", "") or ""
        logger.debug(f"PR body: {pr_body[:200]}...")
        if f"@{assistant_account}" in pr_body:
            mention_text = pr_body
            issue_url = payload.get("pull_request", {}).get("html_url", "")
            issue_title = payload.get("pull_request", {}).get("title", "")
            issue_number = payload.get("pull_request", {}).get("number")

    if not mention_text:
        return False, f"No @{assistant_account} mention found"

    logger.info(f"Will trigger! Issue #{issue_number}: {issue_title}")
    return True, {
        "url": issue_url,
        "title": issue_title,
        "number": issue_number,
        "sender": sender,
        "repo": repo_full_name,
        "event_type": event_type,
        "mention_text": mention_text[:500]
    }


async def spawn_agent_session(trigger_info: dict) -> bool:
    """Spawn an OpenClaw agent session via CLI to handle the issue."""
    openclaw_config = config.get("openclaw", {})
    agent_id = openclaw_config.get("agent_id", "coder")

    # Build session ID: github-{repo_name}-issue-{issue_number}
    repo_name = trigger_info["repo"].split("/")[1]  # genuineClaw/lspyc -> lspyc
    issue_number = trigger_info["number"]
    session_id = f"github-{repo_name}-issue-{issue_number}"

    logger.info(f"Session ID: {session_id}")

    # Build task prompt
    task = f"""You have been summoned via GitHub mention.

**Issue/PR:** {trigger_info['title']}
**Repository:** {trigger_info['repo']}
**From:** @{trigger_info['sender']}
**URL:** {trigger_info['url']}

Please:
1. Read the issue/PR at the URL above using `gh issue view` or `gh pr view`
2. Understand what is being asked
3. Respond appropriately (answer questions, implement changes, etc.)
4. Post your response as a comment using `gh issue comment` or `gh pr comment`

Use the `gh` CLI which is already authenticated as `genuineClaw`.
"""

    # Build CLI command
    cmd = [
        "openclaw", "agent",
        "--agent", agent_id,
        "--session-id", session_id,
        "--message", task,
        "--timeout", "0",  # No timeout
    ]

    logger.info(f"Running: {' '.join(cmd[:6])}... (message truncated)")
    logger.debug(f"Full command: {cmd}")

    try:
        # Run in background (fire and forget)
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        logger.info(f"Spawned process PID: {process.pid}")

        # Don't wait - let it run in background
        # Webhook returns immediately, agent works asynchronously
        return True
    except Exception as e:
        logger.error(f"Failed to spawn agent: {e}")
        return False


@app.post("/webhook")
async def handle_webhook(request: Request):
    """Handle incoming GitHub webhook."""
    logger.info("=" * 60)
    logger.info("Received webhook request")

    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"Client IP: {client_ip}")

    # Log all headers
    headers = dict(request.headers)
    logger.debug("Request headers:")
    for k, v in headers.items():
        logger.debug(f"  {k}: {v}")

    # Get headers
    signature = request.headers.get("x-hub-signature-256", "")
    event_type = request.headers.get("x-github-event", "")
    delivery_id = request.headers.get("x-github-delivery", "")

    logger.info(f"Event type: {event_type}, Delivery ID: {delivery_id}")

    # Get raw body for signature verification
    payload_bytes = await request.body()
    logger.info(f"Payload size: {len(payload_bytes)} bytes")

    if len(payload_bytes) == 0:
        logger.error("Empty payload received!")
        logger.debug(f"Request headers: {dict(request.headers)}")
        raise HTTPException(status_code=400, detail="Empty payload")

    # Check content type - GitHub may send as form-urlencoded or JSON
    content_type = request.headers.get("content-type", "")
    logger.debug(f"Content-Type: {content_type}")

    # Parse payload based on content type
    if "application/x-www-form-urlencoded" in content_type:
        # GitHub sends: payload=%7B%22action%22... (URL-encoded JSON)
        try:
            form_data = urllib.parse.parse_qs(payload_bytes.decode("utf-8"))
            if "payload" in form_data:
                json_str = form_data["payload"][0]
                payload = json.loads(json_str)
                logger.debug(f"Decoded form-urlencoded payload")
            else:
                logger.error("No 'payload' field in form data")
                raise HTTPException(status_code=400, detail="Missing payload field")
        except Exception as e:
            logger.error(f"Failed to parse form data: {e}")
            raise HTTPException(status_code=400, detail="Invalid form data")
    else:
        # Raw JSON
        try:
            payload = json.loads(payload_bytes)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            logger.debug(f"Raw bytes (first 200): {payload_bytes[:200]}")
            raise HTTPException(status_code=400, detail="Invalid JSON")

    # Verify IP comes from GitHub
    if not verify_github_ip(client_ip):
        logger.warning(f"Rejected request from non-GitHub IP: {client_ip}")
        raise HTTPException(status_code=403, detail="IP not allowed")

    # Verify signature
    secret = config.get("webhook", {}).get("secret", "")
    logger.debug(f"Using secret: {'*' * 8 if secret else 'NOT SET'}")
    if not verify_signature(payload_bytes, signature, secret):
        logger.warning(f"Invalid signature for delivery {delivery_id}")
        raise HTTPException(status_code=401, detail="Invalid signature")

    logger.info("Signature verified OK")

    # Log the event
    logger.info(f"Processing {event_type} event, delivery: {delivery_id}")

    # Check if we should trigger
    should, result = should_trigger(payload, event_type)

    if should:
        logger.info(f"Triggering agent spawn for: {result}")
        success = await spawn_agent_session(result)
        if success:
            logger.info("Successfully spawned agent session")
        else:
            logger.error("Failed to spawn agent session")
        return {"status": "triggered", "info": result}
    else:
        logger.info(f"Not triggering: {result}")
        return {"status": "ignored", "reason": result}


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.get("/")
async def root():
    """Root endpoint with basic info."""
    github_config = config.get("github", {})
    return {
        "service": "OpenClaw GitHub Webhook",
        "watched_repos": github_config.get("watched_repos", []),
        "authorized_user": github_config.get("authorized_user"),
        "assistant": github_config.get("assistant_account")
    }


def main():
    """Run the webhook server."""
    port = config.get("webhook", {}).get("port", 8080)
    logger.info(f"Starting webhook server on port {port}")
    logger.info(f"Debug mode: {DEBUG}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="debug")


if __name__ == "__main__":
    main()
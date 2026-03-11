#!/usr/bin/env python3
"""
GitHub Webhook Receiver for OpenClaw Agent

Receives GitHub webhooks, filters for @genuineClaw mentions from authorized user,
and triggers OpenClaw agent to handle the issue/PR.
"""

import json
import hmac
import hashlib
import ipaddress
from pathlib import Path
from typing import Optional
from datetime import datetime

import httpx
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.logger import logger
import uvicorn

# Load config
CONFIG_PATH = Path(__file__).parent / "config.json"
config = json.loads(CONFIG_PATH.read_text()) if CONFIG_PATH.exists() else {}

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
    if not config.get("github_ips_only", True):
        return True
    
    try:
        client_addr = ipaddress.ip_address(client_ip)
        for cidr in GITHUB_IP_RANGES:
            if client_addr in ipaddress.ip_network(cidr):
                return True
    except ValueError:
        pass
    
    return False


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook signature using HMAC-SHA256."""
    if not signature or not signature.startswith("sha256="):
        return False
    
    expected = signature[7:]  # Remove "sha256=" prefix
    
    computed = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(computed, expected)


def extract_mentions(text: str) -> list[str]:
    """Extract all @mentions from text."""
    import re
    if not text:
        return []
    return re.findall(r'@([a-zA-Z0-9-]+)', text)


def should_trigger(payload: dict, event_type: str) -> tuple[bool, Optional[str]]:
    """
    Determine if this webhook should trigger the agent.
    Returns (should_trigger, reason).
    """
    authorized_user = config.get("authorized_user", "pkuGenuine")
    assistant_account = config.get("assistant_account", "genuineClaw")
    watched_repos = config.get("watched_repos", [])
    
    # Check action is "created" (new comment/issue, not edit/delete)
    action = payload.get("action", "")
    if action not in ("created", "opened"):
        return False, f"Action '{action}' ignored (only 'created'/'opened' trigger)"
    
    # Check repository is in watched list
    repo_full_name = payload.get("repository", {}).get("full_name", "")
    if repo_full_name not in watched_repos:
        return False, f"Repo '{repo_full_name}' not in watched repos"
    
    # Check sender is authorized
    sender = payload.get("sender", {}).get("login", "")
    if sender != authorized_user:
        return False, f"Sender '{sender}' not authorized (expected '{authorized_user}')"
    
    # Check for @mention based on event type
    mention_text = None
    issue_url = None
    issue_title = None
    
    if event_type == "issues":
        # New issue created
        issue_body = payload.get("issue", {}).get("body", "")
        if f"@{assistant_account}" in issue_body:
            mention_text = issue_body
            issue_url = payload.get("issue", {}).get("html_url", "")
            issue_title = payload.get("issue", {}).get("title", "")
    
    elif event_type == "issue_comment":
        # New comment on issue/PR
        comment_body = payload.get("comment", {}).get("body", "")
        if f"@{assistant_account}" in comment_body:
            mention_text = comment_body
            issue_url = payload.get("issue", {}).get("html_url", "")
            issue_title = payload.get("issue", {}).get("title", "")
    
    elif event_type == "pull_request":
        # New PR opened
        pr_body = payload.get("pull_request", {}).get("body", "")
        if f"@{assistant_account}" in pr_body:
            mention_text = pr_body
            issue_url = payload.get("pull_request", {}).get("html_url", "")
            issue_title = payload.get("pull_request", {}).get("title", "")
    
    if not mention_text:
        return False, f"No @{assistant_account} mention found"
    
    return True, {
        "url": issue_url,
        "title": issue_title,
        "sender": sender,
        "repo": repo_full_name,
        "event_type": event_type,
        "mention_text": mention_text[:500]  # Truncate for logging
    }


async def trigger_openclaw(trigger_info: dict) -> bool:
    """Send message to OpenClaw to handle the issue."""
    endpoint = config.get("openclaw_endpoint", "http://localhost:3000")
    session = config.get("openclaw_session", "main")
    
    message = f"""GitHub mention detected!

Repo: {trigger_info['repo']}
Title: {trigger_info['title']}
URL: {trigger_info['url']}
From: @{trigger_info['sender']}

Please check and respond to this issue/PR.
"""
    
    # Try sessions_send API
    url = f"{endpoint}/api/sessions/{session}/send"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json={"message": message},
                timeout=10.0
            )
            return response.status_code == 200
    except Exception as e:
        logger.error(f"Failed to trigger OpenClaw: {e}")
        return False


@app.post("/webhook")
async def handle_webhook(request: Request):
    """Handle incoming GitHub webhook."""
    
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    
    # Verify IP comes from GitHub
    if not verify_github_ip(client_ip):
        logger.warning(f"Rejected request from non-GitHub IP: {client_ip}")
        raise HTTPException(status_code=403, detail="IP not allowed")
    
    # Get headers
    signature = request.headers.get("x-hub-signature-256", "")
    event_type = request.headers.get("x-github-event", "")
    delivery_id = request.headers.get("x-github-delivery", "")
    
    # Get raw body for signature verification
    payload_bytes = await request.body()
    
    # Verify signature
    secret = config.get("webhook_secret", "")
    if not verify_signature(payload_bytes, signature, secret):
        logger.warning(f"Invalid signature for delivery {delivery_id}")
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Parse payload
    try:
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    # Log the event
    logger.info(f"Received {event_type} event, delivery: {delivery_id}")
    
    # Check if we should trigger
    should, result = should_trigger(payload, event_type)
    
    if should:
        logger.info(f"Triggering OpenClaw for: {result}")
        success = await trigger_openclaw(result)
        if success:
            logger.info("Successfully triggered OpenClaw")
        else:
            logger.error("Failed to trigger OpenClaw")
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
    return {
        "service": "OpenClaw GitHub Webhook",
        "watched_repos": config.get("watched_repos", []),
        "authorized_user": config.get("authorized_user"),
        "assistant": config.get("assistant_account")
    }


if __name__ == "__main__":
    port = config.get("port", 8080)
    uvicorn.run(app, host="0.0.0.0", port=port)
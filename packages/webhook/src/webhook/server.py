#!/usr/bin/env python3
"""
GitHub Webhook Receiver for OpenClaw Agent

Receives GitHub webhooks, filters for @genuineClaw mentions from authorized user,
and spawns isolated OpenClaw sessions to handle each issue/PR.
"""

import sys
import json
import hmac
import hashlib
import ipaddress
import re
from pathlib import Path
from typing import Optional
from datetime import datetime

try:
    import tomllib
except ImportError:
    import tomli as tomllib

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.logger import logger
import uvicorn

# Find config file (check multiple locations)
CONFIG_PATHS = [
    Path(__file__).parent.parent.parent.parent / "config.toml",  # repo root
    Path(__file__).parent.parent / "config.toml",  # package root
    Path("/etc/claw-infra-kit/config.toml"),  # system config
]


def load_config() -> dict:
    """Load configuration from TOML file."""
    for path in CONFIG_PATHS:
        if path.exists():
            with open(path, "rb") as f:
                return tomllib.load(f)
    logger.warning(f"No config found. Searched: {CONFIG_PATHS}")
    return {}


config = load_config()

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
    if not config.get("webhook", {}).get("github_ips_only", True):
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
    if not text:
        return []
    return re.findall(r'@([a-zA-Z0-9-]+)', text)


def should_trigger(payload: dict, event_type: str) -> tuple[bool, Optional[str]]:
    """
    Determine if this webhook should trigger the agent.
    Returns (should_trigger, info_dict_or_reason_string).
    """
    github_config = config.get("github", {})
    authorized_user = github_config.get("authorized_user", "pkuGenuine")
    assistant_account = github_config.get("assistant_account", "genuineClaw")
    watched_repos = github_config.get("watched_repos", [])
    
    # Check action is "created" or "opened" (not edit/delete)
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
    issue_url = None
    issue_title = None
    issue_number = None
    mention_text = None
    
    if event_type == "issues":
        # New issue created
        issue_body = payload.get("issue", {}).get("body", "")
        if f"@{assistant_account}" in issue_body:
            mention_text = issue_body
            issue_url = payload.get("issue", {}).get("html_url", "")
            issue_title = payload.get("issue", {}).get("title", "")
            issue_number = payload.get("issue", {}).get("number")
    
    elif event_type == "issue_comment":
        # New comment on issue/PR
        comment_body = payload.get("comment", {}).get("body", "")
        if f"@{assistant_account}" in comment_body:
            mention_text = comment_body
            issue_url = payload.get("issue", {}).get("html_url", "")
            issue_title = payload.get("issue", {}).get("title", "")
            issue_number = payload.get("issue", {}).get("number")
    
    elif event_type == "pull_request":
        # New PR opened
        pr_body = payload.get("pull_request", {}).get("body", "")
        if f"@{assistant_account}" in pr_body:
            mention_text = pr_body
            issue_url = payload.get("pull_request", {}).get("html_url", "")
            issue_title = payload.get("pull_request", {}).get("title", "")
            issue_number = payload.get("pull_request", {}).get("number")
    
    if not mention_text:
        return False, f"No @{assistant_account} mention found"
    
    return True, {
        "url": issue_url,
        "title": issue_title,
        "number": issue_number,
        "sender": sender,
        "repo": repo_full_name,
        "event_type": event_type,
        "mention_text": mention_text[:500]  # Truncate for logging
    }


async def spawn_agent_session(trigger_info: dict) -> bool:
    """Spawn an isolated OpenClaw session to handle the issue."""
    openclaw_config = config.get("openclaw", {})
    endpoint = openclaw_config.get("endpoint", "http://localhost:3000")
    agent_id = openclaw_config.get("agent_id", "coder")
    runtime = openclaw_config.get("runtime", "subagent")
    mode = openclaw_config.get("mode", "run")
    
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
    
    # Call sessions_spawn API
    url = f"{endpoint}/api/sessions/spawn"
    
    payload = {
        "task": task,
        "agentId": agent_id,
        "runtime": runtime,
        "mode": mode,
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=payload,
                timeout=10.0
            )
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Spawned session: {result.get('sessionKey', 'unknown')}")
                return True
            else:
                logger.error(f"Failed to spawn session: {response.status_code} {response.text}")
                return False
    except Exception as e:
        logger.error(f"Failed to spawn session: {e}")
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
    secret = config.get("webhook", {}).get("secret", "")
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
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
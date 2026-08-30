import hmac
import hashlib
import time
from typing import Dict, Any, Optional, Tuple


class GitHubWebhookVerifier:
    """Verifies GitHub HMAC-SHA256 signatures and extracts event metadata in < 10ms."""

    @staticmethod
    def verify_signature(payload_bytes: bytes, secret: str, signature_header: Optional[str]) -> bool:
        """Validate the X-Hub-Signature-256 header against the payload and secret."""
        if not secret:
            return True  # If no secret is configured, accept the event in dev/test mode
        if not signature_header or not signature_header.startswith("sha256="):
            return False

        expected_sig = "sha256=" + hmac.new(
            secret.encode("utf-8"),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected_sig, signature_header)

    @staticmethod
    def parse_github_event(event_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Extract repository, commits, and modified files from GitHub webhook."""
        repo = payload.get("repository", {}).get("full_name", "unknown/repo")
        ref = payload.get("ref", "refs/heads/main")
        
        modified_files = set()
        if event_name == "push":
            for commit in payload.get("commits", []):
                modified_files.update(commit.get("added", []))
                modified_files.update(commit.get("modified", []))
        elif event_name in ("pull_request", "pull_request_target"):
            pr = payload.get("pull_request", {})
            ref = pr.get("head", {}).get("ref", ref)
            # Default security files to check if detailed list isn't present
            modified_files.update(["agent/tools.yaml", "prompts/system.md", "mcp/mcp_servers.json"])

        return {
            "event": event_name,
            "repository": repo,
            "ref": ref,
            "modified_files": sorted(list(modified_files)),
            "sender": payload.get("sender", {}).get("login", "unknown"),
        }

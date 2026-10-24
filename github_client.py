"""Read-only GitHub access for teamparallax.

Repository content is treated as untrusted text. It is downloaded and
displayed, never executed.
"""
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple
from urllib.parse import quote

import requests

API_BASE = "https://api.github.com"
RAW_BASE = "https://raw.githubusercontent.com"
TIMEOUT = 15                      # seconds
MAX_FILE_BYTES = 10_000_000       # skip manifests larger than 10 MB
MAX_MANIFESTS = 20                # cap work per scan
MANIFEST_NAMES = ("requirements.txt", "package.json", "package-lock.json")
SKIP_DIRS = {
    "node_modules", ".git", "venv", ".venv", "env", "vendor",
    "dist", "build", "site-packages", "__pycache__", "third_party",
}
USER_AGENT = "teamparallax-hackathon-scanner"

# Matches github.com/<owner>/<repo>, optionally with https://, www., .git,
# or a trailing path such as /tree/main. Anything else is rejected.
_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/"
    r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/?#].*)?$"
)


class GitHubError(Exception):
    """An error whose message is safe and helpful to show to the user."""


@dataclass
class ManifestFile:
    path: str
    content: Optional[str]
    error: Optional[str]


@dataclass
class RepoScan:
    owner: str
    repo: str
    branch: str
    html_url: str
    manifests: List[ManifestFile]
    total_found: int          # manifests found before the MAX_MANIFESTS cap
    tree_truncated: bool      # GitHub said the file listing was incomplete


# ---------- URL validation ----------

def parse_repo_url(url: str) -> Tuple[str, str]:
    match = _URL_RE.match((url or "").strip())
    if not match:
        raise GitHubError(
            "That doesn't look like a GitHub repository URL. "
            "Expected something like https://github.com/owner/repo"
        )
    owner, repo = match.group(1), match.group(2)
    if owner in (".", "..") or repo in (".", ".."):
        raise GitHubError("Invalid repository name in URL.")
    return owner, repo


# ---------- HTTP helpers ----------

def _api_headers() -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    token = os.environ.get("GITHUB_TOKEN")  # optional; read from env only
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _check_status(resp: requests.Response) -> None:
    code = resp.status_code
    if code == 200:
        return
    if code in (403, 429):
        if resp.headers.get("X-RateLimit-Remaining") == "0":
            reset = resp.headers.get("X-RateLimit-Reset", "")
            when = ""
            if reset.isdigit():
                t = datetime.fromtimestamp(int(reset)).strftime("%H:%M")
                when = f" It resets around {t} (local time)."
            raise GitHubError(
                "GitHub API rate limit reached." + when +
                " Unauthenticated requests are limited to 60 per hour. "
                "Setting a GITHUB_TOKEN environment variable raises the limit."
            )
        raise GitHubError(
            "GitHub refused the request (rate limit or access restriction). "
            "Wait a minute and try again."
        )
    if code == 404:
        raise GitHubError(
            "Repository not found. It may not exist, or it may be private. "
            "teamparallax only scans public repositories."
        )
    if code == 409:
        raise GitHubError("This repository is empty, so there is nothing to scan.")
    raise GitHubError(f"GitHub returned an unexpected response (HTTP {code}).")


def _api_get(path: str) -> dict:
    try:
        resp = requests.get(f"{API_BASE}{path}", headers=_api_headers(), timeout=TIMEOUT)
    except requests.Timeout:
        raise GitHubError("GitHub took too long to respond. Please try again.")
    except requests.ConnectionError:
        raise GitHubError("Could not reach GitHub. Check your internet connection.")
    except requests.RequestException as exc:
        raise GitHubError(f"Network error while contacting GitHub ({type(exc).__name__}).")
    _check_status(resp)
    try:
        data = resp.json()
    except ValueError:
        raise GitHubError("GitHub returned a response we could not read.")
    if not isinstance(data, dict):
        raise GitHubError("GitHub returned an unexpected response format.")
    return data


# ---------- GitHub operations ----------

def get_default_branch(owner: str, repo: str) -> str:
    data = _api_get(f"/repos/{quote(owner)}/{quote(repo)}")
    if data.get("private"):
        raise GitHubError("This repository is private. teamparallax only scans public repositories.")
    branch = data.get("default_branch")
    if not isinstance(branch, str) or not branch:
        raise GitHubError("Could not determine the repository's default branch.")
    return branch


def find_manifest_paths(owner: str, repo: str, branch: str) -> Tuple[List[str], bool]:
    data = _api_get(
        f"/repos/{quote(owner)}/{quote(repo)}/git/trees/"
        f"{quote(branch, safe='/')}?recursive=1"
    )
    tree = data.get("tree")
    if not isinstance(tree, list):
        raise GitHubError("Could not read the repository file listing.")
    found = []
    for item in tree:
        if not isinstance(item, dict) or item.get("type") != "blob":
            continue
        path = item.get("path")
        if not isinstance(path, str):
            continue
        parts = path.split("/")
        if parts[-1] not in MANIFEST_NAMES:
            continue
        if any(p in SKIP_DIRS for p in parts[:-1]):
            continue
        found.append(path)
    found.sort(key=lambda p: (p.count("/"), p))   # shallowest first
    return found, bool(data.get("truncated"))


def _decode(raw: bytes) -> str:
    # requirements.txt created by PowerShell redirection is often UTF-16
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def fetch_file(owner: str, repo: str, branch: str, path: str) -> ManifestFile:
    url = (
        f"{RAW_BASE}/{quote(owner)}/{quote(repo)}/"
        f"{quote(branch, safe='/')}/{quote(path, safe='/')}"
    )
    try:
        resp = requests.get(
            url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, stream=True
        )
    except requests.Timeout:
        return ManifestFile(path, None, "Timed out while downloading this file.")
    except requests.RequestException:
        return ManifestFile(path, None, "Network error while downloading this file.")
    try:
        if resp.status_code != 200:
            return ManifestFile(path, None, f"Could not download (HTTP {resp.status_code}).")
        chunks, total = [], 0
        for chunk in resp.iter_content(8192):
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                return ManifestFile(path, None, "File is larger than 1 MB; skipped.")
            chunks.append(chunk)
        return ManifestFile(path, _decode(b"".join(chunks)), None)
    finally:
        resp.close()


def fetch_repo_manifests(url: str) -> RepoScan:
    owner, repo = parse_repo_url(url)
    branch = get_default_branch(owner, repo)
    paths, truncated = find_manifest_paths(owner, repo, branch)
    manifests = [fetch_file(owner, repo, branch, p) for p in paths[:MAX_MANIFESTS]]
    return RepoScan(
        owner=owner,
        repo=repo,
        branch=branch,
        html_url=f"https://github.com/{owner}/{repo}",   # built by us, not taken from the API
        manifests=manifests,
        total_found=len(paths),
        tree_truncated=truncated,
    )
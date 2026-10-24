"""OSV.dev client for teamparallax.

All data returned here comes from OSV.dev. Nothing is invented: if a field is
missing in the OSV record, it stays empty. Responses are untrusted input.
"""
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote

import requests

from parsers import PINNED, Dependency

BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/"
WEB_URL = "https://osv.dev/vulnerability/"
USER_AGENT = "teamparallax-hackathon-scanner"
TIMEOUT = 30
RETRIES = 3
BATCH_SIZE = 500        # OSV allows up to 1000 queries per batch
MAX_PAGES = 5           # follow-up rounds for paginated results
MAX_DETAILS = 150       # cap on advisory detail downloads per scan

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,100}$")

Key = Tuple[str, str, str]   # (ecosystem, package name, exact version)


class OsvError(Exception):
    """Error with a message that is safe to show to the user."""


@dataclass
class Advisory:
    id: str
    summary: str = ""
    details: str = ""
    aliases: List[str] = field(default_factory=list)
    severity_label: Optional[str] = None            # only if the source gives one
    cvss: List[str] = field(default_factory=list)   # raw vector strings, as given
    published: Optional[str] = None
    modified: Optional[str] = None
    references: List[Tuple[str, str]] = field(default_factory=list)
    affected: List[Tuple[str, str, List[str]]] = field(default_factory=list)
    detail_error: Optional[str] = None

    @property
    def url(self) -> str:
        return WEB_URL + quote(self.id)

    @property
    def cves(self) -> List[str]:
        ids = [self.id] + self.aliases
        return list(dict.fromkeys(i for i in ids if i.upper().startswith("CVE-")))

    def fixed_for(self, ecosystem: str, name: str) -> List[str]:
        """Fixed versions the advisory itself lists for this package (never guessed)."""
        out: List[str] = []
        for eco, pkg, fixed in self.affected:
            if eco == ecosystem and pkg == _norm(ecosystem, name):
                out.extend(fixed)
        return list(dict.fromkeys(out))


@dataclass
class DepCheck:
    dep: Dependency
    advisory_ids: List[str]
    error: Optional[str] = None
    partial: bool = False      # results may be incomplete (pagination not finished)


@dataclass
class OsvReport:
    checks: List[DepCheck]
    advisories: Dict[str, Advisory]
    queried_at: str


# ---------- helpers ----------

def _norm(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()   # PEP 503 normalization
    return name


def _str(value, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _request(method: str, url: str, payload=None):
    last = "unknown error"
    for attempt in range(RETRIES):
        try:
            resp = requests.request(
                method, url, json=payload,
                headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT,
            )
        except requests.Timeout:
            last = "request timed out"
        except requests.RequestException:
            last = "network error"
        else:
            code = resp.status_code
            if code == 200:
                try:
                    return resp.json()
                except ValueError:
                    raise OsvError("OSV.dev returned a response we could not read.")
            if code == 404:
                raise OsvError("Not found on OSV.dev (HTTP 404).")
            if code == 429 or code >= 500:
                last = "rate limited (HTTP 429)" if code == 429 else f"server error (HTTP {code})"
            else:
                raise OsvError(f"OSV.dev rejected the request (HTTP {code}).")
        if attempt < RETRIES - 1:
            time.sleep(1.5 * (attempt + 1))
    raise OsvError(f"OSV.dev is unavailable: {last}, after {RETRIES} attempts.")


# ---------- batch version queries ----------

def query_versions(keys: List[Key]):
    """Return (ids_by_key, errors_by_key, partial_keys).

    ids_by_key: advisory IDs OSV matched to that exact package version.
    """
    ids: Dict[Key, List[str]] = {k: [] for k in keys}
    errors: Dict[Key, str] = {}
    partial: Set[Key] = set()
    pending = [(k, None) for k in keys]
    rounds = 0

    while pending and rounds < MAX_PAGES:
        next_pending = []
        for i in range(0, len(pending), BATCH_SIZE):
            chunk = pending[i:i + BATCH_SIZE]
            queries = []
            for (eco, name, ver), token in chunk:
                q = {"package": {"name": _norm(eco, name), "ecosystem": eco}, "version": ver}
                if token:
                    q["page_token"] = token
                queries.append(q)
            try:
                data = _request("POST", BATCH_URL, {"queries": queries})
                results = data.get("results") if isinstance(data, dict) else None
                if not isinstance(results, list) or len(results) != len(chunk):
                    raise OsvError("OSV.dev returned an unexpected response shape.")
            except OsvError as exc:
                for key, _ in chunk:
                    errors.setdefault(key, str(exc))
                continue
            for (key, _), res in zip(chunk, results):
                if not isinstance(res, dict):
                    continue
                for v in res.get("vulns") or []:
                    vid = v.get("id") if isinstance(v, dict) else None
                    if isinstance(vid, str) and _ID_RE.match(vid) and vid not in ids[key]:
                        ids[key].append(vid)
                token = res.get("next_page_token")
                if isinstance(token, str) and token:
                    next_pending.append((key, token))
        pending = next_pending
        rounds += 1

    for key, _ in pending:           # pagination still unfinished
        partial.add(key)
    return ids, errors, partial


# ---------- advisory details ----------

def _parse_vuln(data: dict, vid: str) -> Advisory:
    adv = Advisory(id=vid)
    adv.summary = _str(data.get("summary"), 300)
    adv.details = _str(data.get("details"), 3000)
    adv.published = _str(data.get("published"), 40) or None
    adv.modified = _str(data.get("modified"), 40) or None

    aliases = data.get("aliases")
    if isinstance(aliases, list):
        adv.aliases = [_str(a, 60) for a in aliases[:20] if isinstance(a, str) and a.strip()]

    ds = data.get("database_specific")
    if isinstance(ds, dict) and isinstance(ds.get("severity"), str) and ds["severity"].strip():
        adv.severity_label = ds["severity"].strip().upper()[:20]

    sev = data.get("severity")
    if isinstance(sev, list):
        for s in sev[:5]:
            if isinstance(s, dict) and isinstance(s.get("type"), str) and isinstance(s.get("score"), str):
                adv.cvss.append(f"{_str(s['type'], 20)}: {_str(s['score'], 120)}")

    refs = data.get("references")
    if isinstance(refs, list):
        for r in refs[:30]:
            if isinstance(r, dict) and isinstance(r.get("url"), str):
                url = r["url"].strip()
                if url.startswith(("https://", "http://")) and len(url) < 500:
                    adv.references.append((_str(r.get("type"), 20) or "LINK", url))

    affected = data.get("affected")
    if isinstance(affected, list):
        for a in affected:
            if not isinstance(a, dict) or not isinstance(a.get("package"), dict):
                continue
            eco = a["package"].get("ecosystem")
            name = a["package"].get("name")
            if not isinstance(eco, str) or not isinstance(name, str):
                continue
            fixed: List[str] = []
            for rng in a.get("ranges") or []:
                if isinstance(rng, dict) and rng.get("type") in ("ECOSYSTEM", "SEMVER"):
                    for ev in rng.get("events") or []:
                        if isinstance(ev, dict) and isinstance(ev.get("fixed"), str):
                            fixed.append(_str(ev["fixed"], 60))
            adv.affected.append((eco, _norm(eco, name), list(dict.fromkeys(fixed))))
    return adv


def fetch_advisory(vid: str) -> Advisory:
    try:
        data = _request("GET", VULN_URL + quote(vid))
        if not isinstance(data, dict):
            raise OsvError("Unexpected advisory format.")
        return _parse_vuln(data, vid)
    except OsvError as exc:
        return Advisory(id=vid, detail_error=str(exc))


# ---------- public entry point ----------

def check_dependencies(deps: List[Dependency]) -> OsvReport:
    pinned = [d for d in deps if d.status == PINNED and d.exact_version]
    keys = list(dict.fromkeys((d.ecosystem, d.name, d.exact_version) for d in pinned))
    ids, errors, partial = query_versions(keys) if keys else ({}, {}, set())

    all_ids = list(dict.fromkeys(i for k in keys for i in ids[k]))
    advisories: Dict[str, Advisory] = {}
    to_fetch = all_ids[:MAX_DETAILS]
    if to_fetch:
        with ThreadPoolExecutor(max_workers=8) as pool:
            for adv in pool.map(fetch_advisory, to_fetch):
                advisories[adv.id] = adv
    for vid in all_ids[MAX_DETAILS:]:
        advisories[vid] = Advisory(id=vid, detail_error="Details not fetched (per-scan limit reached).")

    checks = []
    for d in pinned:
        key = (d.ecosystem, d.name, d.exact_version)
        checks.append(DepCheck(
            dep=d,
            advisory_ids=ids.get(key, []),
            error=errors.get(key),
            partial=key in partial,
        ))
    return OsvReport(
        checks=checks,
        advisories=advisories,
        queried_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
"""Parse dependency manifests as plain text.

Nothing here executes, imports, or installs anything from a scanned repo.
All input is treated as untrusted.
"""
import json
import re
from dataclasses import dataclass, field
from typing import List, Optional

PINNED = "Pinned"
RANGE = "Range"
UNPINNED = "No version"
NON_REGISTRY = "Non-registry source"

R_PINNED = "Exact version declared, so it can be looked up directly."
R_RANGE = (
    "A range or wildcard: the version that would actually be installed is "
    "unknown, so an exact-version lookup would be a guess."
)
R_NONE = "No version declared; the installed version cannot be determined from this file."
R_NONREG = (
    "Installed from a URL, VCS, or local path rather than the package "
    "registry; registry advisories cannot be matched reliably."
)
R_LOCK = "Exact installed version from lock file."


@dataclass
class Dependency:
    name: str
    ecosystem: str                 # "PyPI" or "npm"
    declared: str                  # version text exactly as written
    exact_version: Optional[str]   # only set when status == PINNED
    status: str
    reason: str
    dep_type: str                  # runtime / dev / optional
    manifest: str


@dataclass
class ParsedManifest:
    path: str
    ecosystem: str
    dependencies: List[Dependency] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def _clip(text: str, n: int = 80) -> str:
    text = text.strip()
    return text if len(text) <= n else text[: n - 3] + "..."


def _dep(path, eco, name, declared, exact, status, reason, dep_type="runtime"):
    return Dependency(
        name=_clip(name, 100),
        ecosystem=eco,
        declared=_clip(declared, 100),
        exact_version=exact,
        status=status,
        reason=reason,
        dep_type=dep_type,
        manifest=path,
    )


# ---------------- requirements.txt ----------------

_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_REQ = re.compile(rf"^({_NAME})\s*(?:\[[^\]]*\])?\s*(.*)$")
_NAMED_URL = re.compile(rf"^({_NAME})\s*(?:\[[^\]]*\])?\s*@\s*(\S+)")
_COMMENT = re.compile(r"(^|\s)#.*$")
_PY_EXACT = re.compile(r"^==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)$")


def _logical_lines(text: str):
    """Join lines ending in a backslash (used by pip hash-pinned files)."""
    buf = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\") and not line.lstrip().startswith("#"):
            buf += line[:-1] + " "
            continue
        yield buf + line
        buf = ""
    if buf:
        yield buf


def parse_requirements(path: str, content: str) -> ParsedManifest:
    result = ParsedManifest(path=path, ecosystem="PyPI")
    for line in _logical_lines(content):
        line = _COMMENT.sub("", line).strip()
        if not line:
            continue

        if line.startswith("-"):
            result.warnings.append(f"Option line ignored (not followed): {_clip(line)}")
            continue

        m = _NAMED_URL.match(line)
        if m:
            result.dependencies.append(
                _dep(path, "PyPI", m.group(1), "@ " + m.group(2), None, NON_REGISTRY, R_NONREG)
            )
            continue
        if "://" in line or line.startswith(("git+", "file:")):
            egg = re.search(r"#egg=([A-Za-z0-9._-]+)", line)
            result.dependencies.append(
                _dep(path, "PyPI", egg.group(1) if egg else line, line, None, NON_REGISTRY, R_NONREG)
            )
            continue

        line = line.split(";", 1)[0].strip()      # drop environment markers
        m = _REQ.match(line)
        if not m:
            result.warnings.append(f"Unrecognized line skipped: {_clip(line)}")
            continue
        name = m.group(1)
        spec = re.split(r"(?:^|\s)--", m.group(2))[0].strip()   # drop --hash=...

        if not spec:
            result.dependencies.append(_dep(path, "PyPI", name, "(none)", None, UNPINNED, R_NONE))
            continue
        if not re.match(r"^[<>=!~]", spec):
            result.warnings.append(f"Unrecognized version text skipped: {_clip(name + ' ' + spec)}")
            continue

        exact = None
        for clause in spec.split(","):
            em = _PY_EXACT.match(clause.strip())
            if em:
                exact = em.group(1)
                break
        if exact:
            result.dependencies.append(_dep(path, "PyPI", name, spec, exact, PINNED, R_PINNED))
        else:
            result.dependencies.append(_dep(path, "PyPI", name, spec, None, RANGE, R_RANGE))
    return result


# ---------------- package.json ----------------

_NPM_EXACT = re.compile(r"^=?\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$")
_NPM_SECTIONS = {
    "dependencies": "runtime",
    "devDependencies": "dev",
    "optionalDependencies": "optional",
}


def parse_package_json(path: str, content: str) -> ParsedManifest:
    result = ParsedManifest(path=path, ecosystem="npm")
    try:
        data = json.loads(content)
    except (ValueError, RecursionError):
        result.warnings.append("This file is not valid JSON, so no dependencies were extracted.")
        return result
    if not isinstance(data, dict):
        result.warnings.append("Unexpected package.json structure (top level is not an object).")
        return result

    for section, dep_type in _NPM_SECTIONS.items():
        block = data.get(section)
        if block is None:
            continue
        if not isinstance(block, dict):
            result.warnings.append(f"Section '{section}' is not an object; skipped.")
            continue
        for name, value in block.items():
            if not isinstance(name, str) or not isinstance(value, str):
                result.warnings.append(f"Entry in '{section}' has a non-text version; skipped.")
                continue
            v = value.strip()
            if ":" in v or "/" in v:
                result.dependencies.append(
                    _dep(path, "npm", name, v, None, NON_REGISTRY, R_NONREG, dep_type))
                continue
            if v in ("", "*", "x", "latest"):
                result.dependencies.append(
                    _dep(path, "npm", name, v or "(empty)", None, UNPINNED, R_NONE, dep_type))
                continue
            em = _NPM_EXACT.match(v)
            if em:
                result.dependencies.append(
                    _dep(path, "npm", name, v, em.group(1), PINNED, R_PINNED, dep_type))
            else:
                result.dependencies.append(
                    _dep(path, "npm", name, v, None, RANGE, R_RANGE, dep_type))
    return result


# ---------------- package-lock.json ----------------

def parse_package_lock(path: str, content: str) -> ParsedManifest:
    result = ParsedManifest(path=path, ecosystem="npm")
    try:
        data = json.loads(content)
    except (ValueError, RecursionError):
        result.warnings.append("This file is not valid JSON, so no dependencies were extracted.")
        return result
    if not isinstance(data, dict):
        result.warnings.append("Unexpected package-lock.json structure (top level is not an object).")
        return result

    seen = set()

    def _add(name, info):
        if not isinstance(name, str) or not isinstance(info, dict):
            return
        ver = info.get("version")
        if not isinstance(ver, str):
            return
        key = (name, ver)
        if key in seen:
            return
        seen.add(key)

        if info.get("dev") is True:
            dep_type = "dev"
        elif info.get("optional") is True:
            dep_type = "optional"
        else:
            dep_type = "runtime"

        resolved = info.get("resolved")
        resolved_s = resolved if isinstance(resolved, str) else ""
        em = _NPM_EXACT.match(ver)
        nonreg = (
            resolved_s.startswith("git")
            or resolved_s.startswith("file:")
            or resolved_s.startswith("http://")
        )
        if em and not nonreg:
            result.dependencies.append(
                _dep(path, "npm", name, ver, em.group(1), PINNED, R_LOCK, dep_type)
            )
        else:
            result.dependencies.append(
                _dep(path, "npm", name, ver, None, NON_REGISTRY, R_NONREG, dep_type)
            )

    lock_ver = data.get("lockfileVersion")
    if lock_ver in (2, 3):
        packages = data.get("packages")
        if isinstance(packages, dict):
            for pkg_key, info in packages.items():
                if pkg_key == "" or not isinstance(info, dict):
                    continue
                if info.get("link") is True:
                    continue
                if not isinstance(info.get("version"), str):
                    continue
                name = pkg_key.rsplit("node_modules/", 1)[-1]
                _add(name, info)
    elif lock_ver == 1:

        def _walk(deps):
            if not isinstance(deps, dict):
                return
            for name, info in deps.items():
                if not isinstance(info, dict):
                    continue
                _add(name, info)
                nested = info.get("dependencies")
                if nested is not None:
                    _walk(nested)

        _walk(data.get("dependencies"))
    return result


# ---------------- dispatcher ----------------

def parse_manifest(path: str, content: str) -> ParsedManifest:
    base = path.rsplit("/", 1)[-1]
    if base == "requirements.txt":
        return parse_requirements(path, content)
    if base == "package.json":
        return parse_package_json(path, content)
    if base == "package-lock.json":
        return parse_package_lock(path, content)
    return ParsedManifest(path=path, ecosystem="unknown",
                          warnings=["Unsupported manifest type."])
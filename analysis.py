"""Transparent, rule-based prioritization, explanations and remediation.

Everything here derives from fields already retrieved from OSV.dev and the
manifest. Nothing is estimated by a model, and no fix version is ever invented.
"""
import re
from dataclasses import dataclass
from typing import List, Optional

from osv_client import Advisory, OsvReport
from parsers import Dependency

SEVERITY_POINTS = {"CRITICAL": 40, "HIGH": 30, "MODERATE": 20, "MEDIUM": 20, "LOW": 10}
DEP_TYPE_POINTS = {"runtime": 10, "optional": 5, "dev": 0}
NETWORK_POINTS = 10
MULTI_MIN, MULTI_POINTS = 3, 5

TIER_ORDER = ["Urgent", "High", "Needs review", "Medium", "Low"]
_RANK = {t: i for i, t in enumerate(TIER_ORDER)}

RULES_TEXT = [
    "Severity label from the advisory: CRITICAL +40, HIGH +30, MODERATE/MEDIUM +20, LOW +10.",
    "If the advisory gives no (or an unrecognized) severity: +0 and the tier is "
    "'Needs review'. Unknown is never treated as low.",
    "CVSS v3 vector from the advisory shows network attack, no privileges, no user "
    "interaction (AV:N, PR:N, UI:N): +10. We read the vector; we do not compute a CVSS score.",
    "Declared as a runtime dependency +10, optional +5, dev +0.",
    "Three or more advisories match the same package version: +5.",
    "Tiers (only when severity is known): 50+ Urgent, 35-49 High, 25-34 Medium, below 25 Low.",
    "Not assessed: reachability, exploitability, exposure, or whether the code is used.",
]

_V3 = re.compile(r"CVSS:3\.[01]/[A-Za-z0-9:/]+")
_SAFE = re.compile(r"[^A-Za-z0-9@/._+~:-]")


def _safe(text) -> str:
    """Strip anything that could act as markdown from untrusted text."""
    return _SAFE.sub("", str(text))


@dataclass
class Finding:
    dep: Dependency
    adv: Advisory
    n_adv: int
    score: int
    tier: str
    reasons: List[str]
    explanation: str
    fixed_versions: List[str]
    remediation: str


@dataclass
class ChecklistItem:
    key: str
    text: str


def _cvss3_vector(adv: Advisory) -> Optional[str]:
    for s in adv.cvss:
        m = _V3.search(s)
        if m:
            return m.group(0)
    return None


def _tier(score: int, known: bool) -> str:
    if not known:
        return "Needs review"
    if score >= 50:
        return "Urgent"
    if score >= 35:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def score_finding(dep: Dependency, adv: Advisory, n_adv: int):
    score, reasons = 0, []
    label = adv.severity_label
    known = label in SEVERITY_POINTS
    if known:
        pts = SEVERITY_POINTS[label]
        score += pts
        reasons.append(f"+{pts}: advisory reports severity {label}")
    elif label:
        reasons.append(f"+0: severity label '{label}' is not recognized; treated as not provided")
    else:
        reasons.append("+0: advisory provides no severity (unknown is not treated as low)")

    vec = _cvss3_vector(adv)
    if vec:
        if {"AV:N", "PR:N", "UI:N"} <= set(vec.split("/")):
            score += NETWORK_POINTS
            reasons.append(f"+{NETWORK_POINTS}: CVSS v3 vector shows network attack with no "
                           "privileges and no user interaction")
        else:
            reasons.append("+0: CVSS v3 vector present but not network/no-privilege/no-interaction")
    else:
        reasons.append("+0: no CVSS v3 vector provided")

    pts = DEP_TYPE_POINTS.get(dep.dep_type, 0)
    score += pts
    note = " (can still affect build/CI)" if dep.dep_type == "dev" else ""
    reasons.append(f"+{pts}: declared as a {dep.dep_type} dependency{note}")

    if n_adv >= MULTI_MIN:
        score += MULTI_POINTS
        reasons.append(f"+{MULTI_POINTS}: {n_adv} advisories match this package version")

    tier = _tier(score, known)
    if not known:
        reasons.append("Tier: Needs review (severity unknown, so no severity-based tier is assigned)")
    else:
        reasons.append(f"Tier: {tier} (total {score} points)")
    reasons.append("Reachability and exploitability were NOT assessed.")
    return score, tier, reasons


def explain(dep: Dependency, adv: Advisory, n_adv: int) -> str:
    lines = [
        f"{dep.name} {dep.exact_version} ({dep.ecosystem}) is declared in {dep.manifest} "
        f"as a {dep.dep_type} dependency.",
        f"OSV.dev matched this exact version to advisory {adv.id}.",
    ]
    if adv.cves:
        lines.append(f"CVE identifier(s): {', '.join(adv.cves)}.")
    if adv.summary:
        lines.append(f"Advisory summary (from the source): {adv.summary}")
    lines.append(
        f"Severity as provided by the source: {adv.severity_label}."
        if adv.severity_label else "The source does not provide a severity for this advisory."
    )
    if adv.published:
        lines.append(f"Published: {adv.published}.")
    if n_adv > 1:
        lines.append(f"This version matches {n_adv} advisories in total.")
    lines.append(
        "Limits: this is a version match. It does not show that your code calls the "
        "vulnerable code path or that it is exploitable in your deployment."
    )
    return "\n".join(lines)


def remediation_text(dep: Dependency, fixed: List[str]) -> str:
    if fixed:
        return (
            f"The advisory lists these fixed version(s) for {dep.name}: {', '.join(fixed)}.\n"
            f"Currently declared: {dep.exact_version}. An advisory can list one fix per release "
            "line, so choose one that fits your version line and read the project's changelog "
            "before upgrading. Run your tests after changing the version."
        )
    return (
        "No fixed version is listed in this advisory's record, so none is suggested here.\n"
        "Open the advisory references to look for maintainer guidance or a patch. "
        "Do not assume that a newer version is safe."
    )


def build_findings(report: OsvReport) -> List[Finding]:
    out: List[Finding] = []
    for c in report.checks:
        n = len(c.advisory_ids)
        for vid in c.advisory_ids:
            adv = report.advisories.get(vid)
            if adv is None:
                continue
            score, tier, reasons = score_finding(c.dep, adv, n)
            fixed = adv.fixed_for(c.dep.ecosystem, c.dep.name)
            out.append(Finding(
                dep=c.dep, adv=adv, n_adv=n, score=score, tier=tier, reasons=reasons,
                explanation=explain(c.dep, adv, n), fixed_versions=fixed,
                remediation=remediation_text(c.dep, fixed),
            ))
    out.sort(key=lambda f: (_RANK[f.tier], -f.score, f.dep.name, f.adv.id))
    return out


def build_checklist(findings: List[Finding]) -> List[ChecklistItem]:
    groups = {}
    for f in findings:        # findings are already sorted, so groups keep priority order
        key = (f.dep.manifest, f.dep.ecosystem, f.dep.name, f.dep.exact_version)
        g = groups.setdefault(key, {"ids": [], "fixed": []})
        g["ids"].append(f.adv.id)
        g["fixed"].extend(f.fixed_versions)

    items = []
    for (manifest, eco, name, ver), g in groups.items():
        ids = list(dict.fromkeys(g["ids"]))
        fixed = list(dict.fromkeys(g["fixed"]))
        text = (f"`{_safe(name)} {_safe(ver)}` in `{_safe(manifest)}`: review "
                f"{len(ids)} advisory(ies) ({', '.join(_safe(i) for i in ids[:5])}"
                f"{', ...' if len(ids) > 5 else ''}).")
        if fixed:
            text += f" Advisory-listed fixed version(s): {', '.join(_safe(v) for v in fixed)}."
            if len(ids) > 1:
                text += " Pick a version that satisfies every advisory's fix."
        else:
            text += " No fixed version is listed; read the references."
        items.append(ChecklistItem(key=f"chk_{_safe(manifest)}_{_safe(name)}_{_safe(ver)}", text=text))
    return items
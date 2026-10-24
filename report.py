"""Build the exportable JSON security report from real scan results only."""
from datetime import datetime, timezone

from parsers import PINNED

LIMITATIONS = [
    "A finding is a version match against OSV.dev data; it does not show the vulnerable code is reachable or exploitable.",
    "Only requirements.txt and package.json were read. Lock files, pyproject.toml and other formats were not.",
    "Transitive dependencies were not resolved.",
    "Dependencies without an exact version (ranges, no version, non-registry sources) were not checked.",
    "Zero findings does not mean a project is secure; OSV.dev does not know every vulnerability.",
    "Priority is a rule-based triage aid, not a risk rating. Explanations are rule-based, not AI-generated.",
]


def build_report(analysis: dict, findings: list, is_sample: bool) -> dict:
    scan, deps, osv = analysis["scan"], analysis["deps"], analysis["report"]
    return {
        "tool": "teamparallax",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scan_mode": "sample repository (live scan of a demo repo)" if is_sample else "live scan",
        "data_sources": ["GitHub API / raw.githubusercontent.com", "OSV.dev"],
        "repository": {"url": scan.html_url, "default_branch": scan.branch},
        "osv_queried_at_utc": osv.queried_at,
        "summary": {
            "manifests_found": scan.total_found,
            "dependencies_listed": len(deps),
            "checked_via_osv": sum(1 for c in osv.checks if c.error is None),
            "lookup_failures": sum(1 for c in osv.checks if c.error),
            "advisory_matches": len(findings),
            "not_checkable": sum(1 for d in deps if d.status != PINNED),
        },
        "limitations": LIMITATIONS,
        "lookup_errors": [
            {"package": c.dep.name, "version": c.dep.exact_version, "error": c.error}
            for c in osv.checks if c.error
        ],
        "dependencies": [
            {
                "package": d.name, "ecosystem": d.ecosystem, "declared": d.declared,
                "exact_version": d.exact_version, "status": d.status,
                "type": d.dep_type, "manifest": d.manifest,
            }
            for d in deps
        ],
        "findings": [
            {
                "priority": f.tier,
                "score": f.score,
                "priority_reasoning": f.reasons,
                "package": f.dep.name,
                "ecosystem": f.dep.ecosystem,
                "version": f.dep.exact_version,
                "manifest": f.dep.manifest,
                "dependency_type": f.dep.dep_type,
                "advisory_id": f.adv.id,
                "cve_ids": f.adv.cves,
                "aliases": f.adv.aliases,
                "severity_as_provided": f.adv.severity_label,
                "cvss_vectors_as_provided": f.adv.cvss,
                "summary": f.adv.summary,
                "osv_url": f.adv.url,
                "fixed_versions_listed_by_advisory": f.fixed_versions,
                "explanation_rule_based": f.explanation,
                "remediation_guidance": f.remediation,
                "references": [{"type": t, "url": u} for t, u in f.adv.references],
            }
            for f in findings
        ],
    }
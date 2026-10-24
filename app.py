import json
import re
import traceback
from collections import Counter

import pandas as pd
import streamlit as st

from analysis import RULES_TEXT, TIER_ORDER, build_checklist, build_findings
from github_client import GitHubError, MAX_MANIFESTS, fetch_repo_manifests
from osv_client import check_dependencies
from parsers import parse_manifest
from report import build_report

# EDIT THIS: a public repo you control, used for the demo button
SAMPLE_REPO_URL = "https://github.com/preranas03/teamparallax-demo/tree/main"

SAFE_URL = re.compile(r"^https?://[^\s()<>\[\]\"'`]+$")

st.set_page_config(page_title="teamparallax", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
    .tagline { color: #10b981; font-size: 1.2rem; letter-spacing: 0.08em; }
    </style>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("About")
    st.write(
        "teamparallax matches dependency versions against public "
        "vulnerability data (OSV.dev)."
    )
    st.caption(
        "A match is not proof that vulnerable code is reachable, and "
        "zero findings does not mean a project is secure."
    )
    with st.expander("How priority is calculated"):
        for rule in RULES_TEXT:
            st.text("- " + rule)


def run_scan(url: str) -> dict:
    with st.spinner("Fetching manifests from GitHub..."):
        scan = fetch_repo_manifests(url)
    parsed = [
        parse_manifest(m.path, m.content)
        for m in scan.manifests
        if m.error is None and m.content is not None
    ]
    deps = [d for p in parsed for d in p.dependencies]
    with st.spinner("Querying OSV.dev for known advisories..."):
        report = check_dependencies(deps)
    is_sample = url.strip().rstrip("/").lower() == SAMPLE_REPO_URL.lower()
    return {"scan": scan, "parsed": parsed, "deps": deps, "report": report,
            "is_sample": is_sample}


def use_sample():
    st.session_state["repo_url"] = SAMPLE_REPO_URL


st.title("🛡️ teamparallax")
st.markdown('<div class="tagline">Scan. Detect. Explain. Fix.</div>', unsafe_allow_html=True)
st.write("")

repo_url = st.text_input(
    "Public GitHub repository URL",
    placeholder="https://github.com/owner/repo",
    key="repo_url",
)
b1, b2, _ = st.columns([1, 1.3, 4])
scan_clicked = b1.button("Scan repository", type="primary")
sample_clicked = b2.button("Scan sample repo", on_click=use_sample)

if scan_clicked or sample_clicked:
    url = st.session_state.get("repo_url", "")
    if not url.strip():
        st.warning("Please enter a repository URL.")
    elif "YOUR_USERNAME" in url:
        st.warning("Edit SAMPLE_REPO_URL at the top of app.py to your demo repository first.")
    else:
        try:
            st.session_state["analysis"] = run_scan(url)
        except GitHubError as exc:
            st.session_state.pop("analysis", None)
            st.error(str(exc))
        except Exception as exc:  # last-resort guard: never show a raw traceback in the UI
            st.session_state.pop("analysis", None)
            traceback.print_exc()   # full details go to the terminal only
            st.error(
                f"Unexpected error ({type(exc).__name__}). Please try again. "
                "Technical details were written to the terminal."
            )

analysis = st.session_state.get("analysis")

if analysis:
    scan, parsed, deps, report = (
        analysis["scan"], analysis["parsed"], analysis["deps"], analysis["report"],
    )
    is_sample = analysis.get("is_sample", False)
    findings = build_findings(report)

    if is_sample:
        st.info(
            "SAMPLE REPOSITORY: this is a live scan of a small demo repo we created with "
            "deliberately old package versions. It is not the security status of a real project."
        )
    else:
        st.success("Repository fetched (live data from GitHub).")
    st.markdown(f"Source: [{scan.html_url}]({scan.html_url})")

    if scan.total_found > MAX_MANIFESTS:
        st.warning(
            f"{scan.total_found} manifests found; only the first {MAX_MANIFESTS} "
            "(shallowest paths first) were downloaded."
        )
    if scan.tree_truncated:
        st.warning(
            "GitHub reported that the file listing for this repository was "
            "incomplete, so some manifests may have been missed."
        )

    checked_ok = sum(1 for c in report.checks if c.error is None)
    failed = [c for c in report.checks if c.error]
    vulnerable_deps = sum(1 for c in report.checks if c.advisory_ids)
    not_checkable = len(deps) - len(report.checks)

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Dependencies listed", len(deps))
    m2.metric("Checked via OSV", checked_ok)
    m3.metric("Dependencies with matches", vulnerable_deps)
    m4.metric("Advisory matches", len(findings))
    m5.metric("Not checkable", not_checkable)
    st.caption(
        f"Live OSV.dev query at {report.queried_at} (UTC). A match means the declared exact "
        "version falls inside an advisory's affected range. It does not show that vulnerable "
        "code is reachable or exploitable in this project. Transitive dependencies are not resolved."
    )

    # ---- JSON export ----
    report_json = json.dumps(build_report(analysis, findings, is_sample), indent=2)
    fname = re.sub(r"[^A-Za-z0-9._-]", "_", f"teamparallax-report-{scan.owner}-{scan.repo}.json")
    st.download_button(
        "⬇️ Download JSON security report",
        data=report_json,
        file_name=fname,
        mime="application/json",
    )

    if failed:
        st.warning(
            f"{len(failed)} dependencies could not be checked because OSV.dev lookups failed. "
            "Their status is UNKNOWN, not safe."
        )
        with st.expander("Lookup errors"):
            for c in failed:
                st.text(f"{c.dep.name} {c.dep.exact_version}: {c.error}")
    if any(c.partial for c in report.checks):
        st.warning("Some results were paginated and may be incomplete.")

    # ---------------- findings ----------------
    st.subheader("Findings")
    if not report.checks:
        st.info(
            "No dependency had an exact version, so nothing was sent to OSV.dev. "
            "This is not a clean result."
        )
    elif not findings:
        st.info(
            f"OSV.dev returned no advisories for the {checked_ok} exact versions it checked. "
            "This is not proof the project is secure: unpinned, non-registry, and "
            "transitive dependencies were not checked, and OSV does not know every vulnerability."
        )
    else:
        counts = Counter(f.tier for f in findings)
        st.caption(
            "By priority: "
            + ", ".join(f"{t} {counts[t]}" for t in TIER_ORDER if counts[t])
            + ". Priority comes from transparent rules (see the sidebar), not from a model."
        )

        rows = []
        for f in findings:
            rows.append({
                "Priority": f.tier,
                "Score": f.score,
                "Package": f.dep.name,
                "Ecosystem": f.dep.ecosystem,
                "Version": f.dep.exact_version,
                "Advisory": f.adv.id,
                "CVE": ", ".join(f.adv.cves) or "—",
                "Severity (as provided)": f.adv.severity_label or "Not provided",
                "Fix listed": "Yes" if f.fixed_versions else "No",
                "Summary": f.adv.summary or (
                    f"(details unavailable: {f.adv.detail_error})" if f.adv.detail_error else "—"),
                "OSV link": f.adv.url,
            })
        fdf = pd.DataFrame(rows)

        f1, f2, f3 = st.columns(3)
        pri_opts = [t for t in TIER_ORDER if t in set(fdf["Priority"])]
        sev_opts = sorted(fdf["Severity (as provided)"].unique())
        eco_opts = sorted(fdf["Ecosystem"].unique())
        pri_pick = f1.multiselect("Filter by priority", pri_opts, default=pri_opts)
        sev_pick = f2.multiselect("Filter by severity", sev_opts, default=sev_opts)
        eco_pick = f3.multiselect("Filter by ecosystem", eco_opts, default=eco_opts, key="eco_f")
        view = fdf[
            fdf["Priority"].isin(pri_pick)
            & fdf["Severity (as provided)"].isin(sev_pick)
            & fdf["Ecosystem"].isin(eco_pick)
        ]
        st.dataframe(
            view,
            hide_index=True,
            column_config={"OSV link": st.column_config.LinkColumn("OSV link", display_text="Open")},
        )
        st.caption("Severity is shown only when the advisory source provides it; we never estimate it.")

        # ---------------- finding detail ----------------
        st.subheader("Finding details")
        idx = st.selectbox(
            "Inspect a finding",
            range(len(findings)),
            format_func=lambda i: (
                f"[{findings[i].tier}] {findings[i].adv.id} — "
                f"{findings[i].dep.name} {findings[i].dep.exact_version}"
            ),
        )
        f = findings[idx]
        adv = f.adv

        st.markdown(f"**Priority: {f.tier}** (score {f.score}) · [Open {adv.id} on OSV.dev]({adv.url})")

        st.markdown("**Why this priority**")
        st.text("\n".join(f.reasons))

        st.markdown("**Explanation** (rule-based from advisory data, not AI-generated)")
        st.text(f.explanation)

        st.markdown("**Remediation** (only from the advisory's own data)")
        st.text(f.remediation)

        if adv.detail_error:
            st.warning(f"Full advisory details unavailable: {adv.detail_error}")
        st.text(f"Aliases: {', '.join(adv.aliases) or '—'}")
        st.text(f"CVSS vector(s): {'; '.join(adv.cvss) or 'Not provided'}")
        st.text(f"Published: {adv.published or '—'}    Modified: {adv.modified or '—'}")
        if adv.details:
            with st.expander("Advisory text (untrusted, shown as plain text)"):
                st.text(adv.details)
        if adv.references:
            st.markdown("**References listed by the advisory**")
            for rtype, url in adv.references[:15]:
                label = re.sub(r"[^A-Za-z]", "", rtype) or "LINK"
                if SAFE_URL.match(url):
                    st.markdown(f"- [{label}]({url})")
                else:
                    st.text(f"- {label}: {url}")

        # ---------------- remediation checklist ----------------
        st.subheader("Remediation checklist")
        st.caption(
            "teamparallax never changes your repository or opens pull requests. "
            "These are steps for a human to review and perform."
        )
        st.markdown("**Affected dependencies** (highest priority first)")
        for item in build_checklist(findings):
            st.checkbox(item.text, key=item.key)
        st.markdown("**Process**")
        for i, step in enumerate([
            "Create a separate branch; do not edit the main branch directly.",
            "Update the affected versions in the manifest, using fixed versions from the advisories.",
            "Install and run your test suite.",
            "Rescan with teamparallax to confirm the advisories no longer match.",
            "Open a pull request and have a teammate review it before merging.",
        ]):
            st.checkbox(step, key=f"proc_{i}")

    # ---------------- dependencies ----------------
    if not scan.manifests:
        st.info(
            "No supported manifests (requirements.txt, package.json) were found. "
            "This does NOT mean the project has no dependencies. It may use formats "
            "we don't support yet, such as pyproject.toml or lock files."
        )
    elif not deps:
        st.info("Manifests were found, but no dependencies could be extracted from them.")
    else:
        if not_checkable > 0:
            st.warning(
                f"{not_checkable} dependencies have no exact version (ranges, no version, or "
                "non-registry sources) and were NOT checked against OSV."
            )
        df = pd.DataFrame([
            {
                "Package": d.name, "Ecosystem": d.ecosystem, "Declared": d.declared,
                "Exact version": d.exact_version or "—", "Status": d.status,
                "Type": d.dep_type, "Manifest": d.manifest, "Why": d.reason,
            }
            for d in deps
        ])
        st.subheader("Dependencies")
        g1, g2 = st.columns(2)
        s_opts = sorted(df["Status"].unique())
        e_opts = sorted(df["Ecosystem"].unique())
        s_pick = g1.multiselect("Filter by status", s_opts, default=s_opts)
        e_pick = g2.multiselect("Filter by ecosystem", e_opts, default=e_opts, key="eco_d")
        st.dataframe(df[df["Status"].isin(s_pick) & df["Ecosystem"].isin(e_pick)], hide_index=True)

    notes = [(p.path, w) for p in parsed for w in p.warnings]
    if notes:
        with st.expander(f"Parser notes ({len(notes)})"):
            for path, w in notes:
                st.text(f"{path}: {w}")

    for m in scan.manifests:
        with st.expander(f"Raw content: {m.path}"):
            if m.error:
                st.warning(m.error)
            else:
                st.code(m.content, language="json" if m.path.endswith(".json") else "text")
else:
    c1, c2, c3 = st.columns(3)
    c1.metric("Dependencies", "—")
    c2.metric("Advisory matches", "—")
    c3.metric("Unpinned / unchecked", "—")
    st.caption("No scan has been run yet. These values will be filled from real scan results.")
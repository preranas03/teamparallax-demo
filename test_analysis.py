from analysis import build_checklist, build_findings, score_finding
from osv_client import Advisory, DepCheck, OsvReport
from parsers import PINNED, Dependency


def dep(name="foo", ver="1.0.0", typ="runtime"):
    return Dependency(name, "npm", ver, ver, PINNED, "test", typ, "package.json")


VEC = "CVSS_V3: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

s, t, r = score_finding(dep(), Advisory(id="T", severity_label="CRITICAL", cvss=[VEC]), 1)
assert (s, t) == (60, "Urgent"), (s, t)
assert score_finding(dep(typ="dev"), Advisory(id="T", severity_label="HIGH"), 1)[:2] == (30, "Medium")
assert score_finding(dep(typ="dev"), Advisory(id="T", severity_label="CRITICAL"), 1)[:2] == (40, "High")
assert score_finding(dep(), Advisory(id="T", severity_label="MODERATE"), 3)[:2] == (35, "High")
assert score_finding(dep(typ="dev"), Advisory(id="T", severity_label="LOW"), 1)[:2] == (10, "Low")

s, t, r = score_finding(dep(), Advisory(id="T"), 1)
assert (s, t) == (10, "Needs review")
assert any("not treated as low" in x for x in r)
assert score_finding(dep(), Advisory(id="T", severity_label="WEIRD"), 1)[1] == "Needs review"

a1 = Advisory(id="T-1", severity_label="CRITICAL", cvss=[VEC], summary="Example",
              affected=[("npm", "foo", ["1.2.3"])])
a2 = Advisory(id="T-2", severity_label="LOW")
report = OsvReport(
    checks=[DepCheck(dep(), ["T-2", "T-1"]), DepCheck(dep("bar"), [])],
    advisories={"T-1": a1, "T-2": a2},
    queried_at="now",
)
fs = build_findings(report)
assert [f.adv.id for f in fs] == ["T-1", "T-2"]            # sorted by priority
assert fs[0].fixed_versions == ["1.2.3"] and "1.2.3" in fs[0].remediation
assert fs[1].fixed_versions == []
assert "1.2.3" not in fs[1].remediation and "No fixed version" in fs[1].remediation
assert "not show that your code calls" in fs[0].explanation

items = build_checklist(fs)
assert len(items) == 1 and "1.2.3" in items[0].text and "satisfies every" in items[0].text

print("All analysis tests passed.")
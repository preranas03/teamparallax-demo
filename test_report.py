import json

from analysis import build_findings
from osv_client import Advisory, DepCheck, OsvReport
from parsers import PINNED, RANGE, Dependency
from report import build_report


class S:  # minimal stand-in for a RepoScan
    html_url, branch, total_found = "https://github.com/o/r", "main", 1


d1 = Dependency("foo", "npm", "1.0.0", "1.0.0", PINNED, "t", "runtime", "package.json")
d2 = Dependency("bar", "npm", "^1.0.0", None, RANGE, "t", "runtime", "package.json")
adv = Advisory(id="T-1", severity_label="HIGH", affected=[("npm", "foo", ["1.1.0"])])
osv = OsvReport([DepCheck(d1, ["T-1"])], {"T-1": adv}, "now")
analysis = {"scan": S(), "deps": [d1, d2], "report": osv}

rep = build_report(analysis, build_findings(osv), is_sample=True)
rep = json.loads(json.dumps(rep))            # must be valid JSON
assert rep["summary"]["advisory_matches"] == 1
assert rep["summary"]["not_checkable"] == 1
assert rep["findings"][0]["fixed_versions_listed_by_advisory"] == ["1.1.0"]
assert "sample" in rep["scan_mode"]
assert len(rep["limitations"]) >= 5
print("Report tests passed.")
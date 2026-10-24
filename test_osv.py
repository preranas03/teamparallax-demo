from osv_client import Advisory, _norm, _parse_vuln

FAKE = {
    "id": "GHSA-test-0000-0000",
    "aliases": ["CVE-0000-0000"],
    "summary": "Example summary",
    "details": "Example details",
    "database_specific": {"severity": "high"},
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"ecosystem": "npm", "name": "foo"},
        "ranges": [
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]},
            {"type": "GIT", "events": [{"fixed": "abcdef"}]},
        ],
    }],
    "references": [
        {"type": "WEB", "url": "https://example.com/x"},
        {"type": "WEB", "url": "javascript:alert(1)"},
    ],
}

adv = _parse_vuln(FAKE, "GHSA-test-0000-0000")
assert adv.severity_label == "HIGH"
assert adv.cves == ["CVE-0000-0000"]
assert adv.fixed_for("npm", "foo") == ["1.2.3"]      # GIT range ignored
assert adv.fixed_for("npm", "bar") == []
assert adv.references == [("WEB", "https://example.com/x")]   # unsafe URL dropped
assert adv.url == "https://osv.dev/vulnerability/GHSA-test-0000-0000"

bare = _parse_vuln({"id": "X-1"}, "X-1")
assert bare.severity_label is None and bare.cvss == [] and bare.fixed_for("npm", "foo") == []

assert _norm("PyPI", "Flask_SQLAlchemy.X") == "flask-sqlalchemy-x"
assert _norm("npm", "Lodash") == "Lodash"

print("All OSV parsing tests passed.")
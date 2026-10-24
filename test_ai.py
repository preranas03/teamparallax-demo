import os

from ai_explain import AiError, ai_explain, build_prompt
from analysis import build_findings
from osv_client import Advisory, DepCheck, OsvReport
from parsers import PINNED, Dependency

d = Dependency("foo", "npm", "1.0.0", "1.0.0", PINNED, "t", "runtime", "package.json")
a = Advisory(id="T-1", summary="Example summary", affected=[("npm", "foo", ["1.2.3"])])
f = build_findings(OsvReport([DepCheck(d, ["T-1"])], {"T-1": a}, "now"))[0]

p = build_prompt(f)
assert "1.2.3" in p and "Example summary" in p
assert "not provided" in p and "<advisory>" in p

os.environ.pop("GROQ_API_KEY", None)
try:
    ai_explain(f)
    raise SystemExit("expected AiError")
except AiError:
    pass

print("AI tests passed.")
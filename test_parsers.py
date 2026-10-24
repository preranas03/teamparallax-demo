from parsers import NON_REGISTRY, PINNED, RANGE, UNPINNED, parse_manifest

REQ = """\
# a comment
flask==0.12.2
requests==2.19.0  # inline comment
pyyaml==5.3
numpy>=1.20
django
Jinja2[i18n]==2.10 ; python_version >= "3.6"
pkg-a==1.*
-r other.txt
git+https://github.com/x/y.git#egg=ypkg
mylib @ https://example.com/mylib.zip
hashed==1.0 \\
    --hash=sha256:abc
"""

m = parse_manifest("requirements.txt", REQ)
d = {x.name: x for x in m.dependencies}
assert len(m.dependencies) == 10, len(m.dependencies)
assert d["flask"].status == PINNED and d["flask"].exact_version == "0.12.2"
assert d["requests"].exact_version == "2.19.0"
assert d["pyyaml"].exact_version == "5.3"
assert d["numpy"].status == RANGE and d["numpy"].exact_version is None
assert d["django"].status == UNPINNED
assert d["Jinja2"].status == PINNED and d["Jinja2"].exact_version == "2.10"
assert d["pkg-a"].status == RANGE
assert d["ypkg"].status == NON_REGISTRY
assert d["mylib"].status == NON_REGISTRY
assert d["hashed"].status == PINNED and d["hashed"].exact_version == "1.0"
assert len(m.warnings) == 1

PKG = (
    '{"name":"x","dependencies":{"lodash":"4.17.15","express":"^4.17.1",'
    '"minimist":"1.2.0","star":"*","mylib":"github:user/repo","local":"file:../local"},'
    '"devDependencies":{"jest":"~29.0.0","exact":"v1.2.3"}}'
)
m = parse_manifest("package.json", PKG)
d = {x.name: x for x in m.dependencies}
assert len(m.dependencies) == 8, len(m.dependencies)
assert d["lodash"].status == PINNED and d["lodash"].exact_version == "4.17.15"
assert d["express"].status == RANGE
assert d["minimist"].exact_version == "1.2.0"
assert d["star"].status == UNPINNED
assert d["mylib"].status == NON_REGISTRY
assert d["local"].status == NON_REGISTRY
assert d["jest"].status == RANGE and d["jest"].dep_type == "dev"
assert d["exact"].status == PINNED and d["exact"].exact_version == "1.2.3"

bad = parse_manifest("package.json", "{not json")
assert bad.dependencies == [] and len(bad.warnings) == 1

print("All parser tests passed.")
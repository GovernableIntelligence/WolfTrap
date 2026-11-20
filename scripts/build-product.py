"""Build the review candidate from immutable Git blobs with the pinned setuptools wheel."""

import argparse
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib
import venv
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BUILDER = "setuptools-84.2.1-py3-none-any.whl"
BUILDER_SHA256 = "ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2"
RECORD = "data/product-build-v1.json"


def check(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def dump(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def git(*args):
    env = {"PATH": os.defpath, "LC_ALL": "C", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_ALLOW_PROTOCOL": ""}
    return subprocess.check_output(["git", *args], cwd=ROOT, env=env)


def sources(head, staging):
    check(re.fullmatch("[0-9a-f]{40}", head) and git("rev-parse", "HEAD").decode().strip() == head, "pin the exact source checkout")
    check(git("show", head + ":scripts/build-product.py") == Path(__file__).read_bytes(), "builder differs from pinned source")
    tree = git("rev-parse", head + "^{tree}").decode().strip()
    rows = git("ls-tree", "-rz", head, "--", "LICENSE", "README.md", "pyproject.toml", "src/wolftrap").split(b"\0")[:-1]
    check(3 < len(rows) < 256, "source count outside build bounds")
    members, total = {}, 0
    for row in rows:
        header, name = row.split(b"\t", 1)
        mode, typ, oid = header.split()
        rel = Path(name.decode("ascii"))
        check(mode == b"100644" and typ == b"blob" and not rel.is_absolute() and ".." not in rel.parts, "unexpected source entry")
        raw = git("cat-file", "blob", oid.decode())
        total += len(raw)
        check(len(raw) <= 1024 * 1024 and total <= 8 * 1024 * 1024, "source size outside build bounds")
        path = staging / rel
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_bytes(raw)
        if rel.is_relative_to("src/wolftrap"):
            members[rel.relative_to("src/wolftrap").as_posix()] = sha(raw)
    project = tomllib.loads((staging / "pyproject.toml").read_text())["project"]
    check(project["dependencies"] == [] and project["license"] == "Apache-2.0" and project["name"] == "wolftrap", "package contract changed")
    version = project["version"]
    record = {"schema": "wolftrap.product-build/v1", "version": version, "commit": head, "tree": tree, "members": members}
    check(RECORD not in members, "unexpected pre-existing build record")
    raw = dump(record)
    (staging / "src/wolftrap" / RECORD).write_bytes(raw)
    return record, {**members, RECORD: sha(raw)}


def checked_wheel(original, members, version):
    """Verify PEP 427 inventory and RECORD, then normalize ZIP metadata independently of zlib."""
    dist = "wolftrap-" + version + ".dist-info/"
    metadata = {"METADATA", "WHEEL", "RECORD", "entry_points.txt", "top_level.txt", "licenses/LICENSE"}
    expected = {"wolftrap/" + k for k in members} | {dist + n for n in metadata}
    target = io.BytesIO()
    with zipfile.ZipFile(original) as archive, zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as result:
        check(len(archive.infolist()) == len(expected) and set(archive.namelist()) == expected, "unexpected wheel contents")
        record = list(csv.reader(io.StringIO(archive.read(dist + "RECORD").decode())))
        check(len(record) == len(expected) and {r[0] for r in record} == expected, "incomplete wheel RECORD")
        for name, signature, size in sorted(record):
            raw = archive.read(name)
            if name == dist + "RECORD":
                check((signature, size) == ("", ""), "unexpected RECORD self hash")
            else:
                digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
                check(signature == "sha256=" + digest and size == str(len(raw)), "wheel RECORD disagreement")
            if name.startswith("wolftrap/"):
                check(sha(raw) == members[name.removeprefix("wolftrap/")], "package differs from source")
            elif name == dist + "entry_points.txt":
                check(raw.strip() == b"[console_scripts]\nwolftrap = wolftrap.cli:main", "unexpected executable entry point")
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            result.writestr(info, raw)
    return target.getvalue()


def build(head, tools, out):
    out = out.absolute()
    check(not out.is_relative_to(ROOT) and out == out.resolve() and not out.exists(), "choose a fresh external build directory")
    dep = tools.absolute() / BUILDER
    check(not dep.is_symlink() and dep.is_file() and dep.stat().st_size < 2_000_000, "supply the locked build wheel")
    backend = dep.read_bytes()
    check(sha(backend) == BUILDER_SHA256, "wrong setuptools wheel pin")
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        project = base / "source"
        record, members = sources(head, project)
        version = record["version"]
        wheels = base / "wheels"
        wheels.mkdir()
        (wheels / BUILDER).write_bytes(backend)
        lock = base / "builder.lock"
        lock.write_bytes(git("show", head + ":.github/product-builder.lock"))
        env = {"PATH": os.defpath, "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "315532800",
               "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        venv.EnvBuilder(with_pip=True).create(base / "backend")
        python = base / "backend/bin/python"
        subprocess.run([python, "-I", "-m", "pip", "--isolated", "install", "--disable-pip-version-check", "--no-cache-dir",
                        "--no-index", "--no-deps", "--only-binary=:all:", "--require-hashes", "--find-links", wheels,
                        "-r", lock], env=env, check=True, stdout=subprocess.DEVNULL)
        subprocess.run([python, "-I", "-c", "import setuptools.build_meta as b; b.build_wheel('../wheels')"],
                       cwd=project, env=env, check=True, stdout=subprocess.DEVNULL)
        name = "wolftrap-" + version + "-py3-none-any.whl"
        result = checked_wheel(wheels / name, members, version)
    pin = sha(result)
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "bom-ref": "wolftrap-core", "name": "wolftrap",
                         "version": version, "licenses": [{"license": {"id": "Apache-2.0"}}],
                         "hashes": [{"alg": "SHA-256", "content": pin}],
                         "properties": [{"name": "wolftrap:source:commit", "value": head},
                                        {"name": "wolftrap:source:tree", "value": record["tree"]},
                                        {"name": "wolftrap:scope", "value": "installed offline core; excludes interpreter, build tools and optional extras"}]}},
            "components": [], "dependencies": [{"ref": "wolftrap-core", "dependsOn": []}]}
    out.mkdir(mode=0o700)
    (out / name).write_bytes(result)
    (out / "core.cdx.json").write_bytes(dump(sbom))
    (out / "SHA256SUMS").write_text(pin + "  " + name + "\n" + sha(dump(sbom)) + "  core.cdx.json\n")
    print(name, pin)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--expected-head", required=True)
    p.add_argument("--wheelhouse", required=True, type=Path)
    p.add_argument("--output-dir", required=True, type=Path)
    args = p.parse_args()
    build(args.expected_head, args.wheelhouse, args.output_dir)

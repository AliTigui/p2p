#!/usr/bin/env python3
"""Generate a deterministic SPDX 2.3 SBOM from locked Cargo metadata.

The SBOM describes the Cargo package graph resolved by ``cargo metadata
--locked``. It does not analyze compiled binaries, vendor source, or runtime
behavior. Local checkout paths are normalized to workspace-relative paths and
the creation timestamp is fixed so identical lockfiles produce identical JSON.

Usage:

    python3 scripts/generate_sbom.py \
      --manifest-path Cargo.toml \
      --workspace-name root \
      --output sbom/root.spdx.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
CREATED = "1970-01-01T00:00:00Z"
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
SPDX_ID_SANITIZER = re.compile(r"[^A-Za-z0-9.-]+")
LICENSE_SLASH = re.compile(r"\s*/\s*")


def normalize_license(value: str | None) -> str:
    """Normalize whitespace and deprecated SPDX slash separators."""
    if not value:
        return "NOASSERTION"
    text = " ".join(value.split())
    if not text:
        return "NOASSERTION"
    return LICENSE_SLASH.sub(" OR ", text)


def normalize_path_text(value: str) -> str:
    """Normalize Windows separators without resolving local checkout paths."""
    return value.replace("\\", "/")


def relative_manifest(package: dict[str, Any], workspace_root: Path) -> str:
    """Return a stable workspace-relative manifest path."""
    raw = normalize_path_text(str(package["manifest_path"]))
    root = normalize_path_text(str(workspace_root)).rstrip("/")
    path = Path(raw)
    base = Path(root)
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return Path(os.path.relpath(raw, root)).as_posix()


def canonical_key(package: dict[str, Any], workspace_root: Path) -> str:
    """Build a checkout-independent identity for one Cargo package."""
    name = package["name"]
    version = package["version"]
    source = package.get("source")
    if source == CRATES_IO_SOURCE:
        return f"registry:crates.io/{name}@{version}"
    if source:
        return f"source:{normalize_path_text(str(source))}/{name}@{version}"
    return f"path:{relative_manifest(package, workspace_root)}#{name}@{version}"


def package_spdx_id(package: dict[str, Any], workspace_root: Path) -> str:
    """Return a valid, deterministic SPDX identifier for one Cargo package."""
    key = canonical_key(package, workspace_root)
    readable = key.split("#", 1)[-1].split("/")[-1]
    readable = SPDX_ID_SANITIZER.sub("-", readable).strip("-.")[:80] or "Package"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:10]
    return f"SPDXRef-Package-{readable}-{digest}"


def download_location(package: dict[str, Any]) -> str:
    """Return a crates.io download URL only when the source is crates.io."""
    if package.get("source") != CRATES_IO_SOURCE:
        return "NOASSERTION"
    name = quote(str(package["name"]), safe="")
    version = quote(str(package["version"]), safe="")
    return f"https://crates.io/api/v1/crates/{name}/{version}/download"


def external_refs(package: dict[str, Any], workspace_root: Path) -> list[dict[str, str]]:
    """Add a cargo purl and a checkout-independent manifest locator."""
    name = quote(str(package["name"]), safe="")
    version = quote(str(package["version"]), safe="")
    purl = f"pkg:cargo/{name}@{version}"
    if not package.get("source"):
        manifest = quote(relative_manifest(package, workspace_root), safe="/")
        purl = f"{purl}?manifest_path={manifest}"
    return [
        {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl,
        },
        {
            "referenceCategory": "OTHER",
            "referenceType": "cargo-manifest",
            "referenceLocator": relative_manifest(package, workspace_root),
        },
    ]


def build_document(
    metadata: dict[str, Any], workspace_name: str, lockfile_sha256: str
) -> dict[str, Any]:
    """Build one SPDX document from cargo metadata and a lockfile digest."""
    workspace_root = Path(normalize_path_text(str(metadata["workspace_root"])))
    packages = metadata["packages"]
    ids = {
        package["id"]: package_spdx_id(package, workspace_root) for package in packages
    }
    if len(set(ids.values())) != len(ids):
        raise ValueError("duplicate SPDX package identifiers")

    spdx_packages: list[dict[str, Any]] = []
    for package in packages:
        license_expression = normalize_license(package.get("license"))
        spdx_packages.append(
            {
                "name": package["name"],
                "SPDXID": ids[package["id"]],
                "versionInfo": package["version"],
                "downloadLocation": download_location(package),
                "filesAnalyzed": False,
                "licenseConcluded": license_expression,
                "licenseDeclared": license_expression,
                "copyrightText": "NOASSERTION",
                "supplier": (
                    "Organization: crates.io"
                    if package.get("source") == CRATES_IO_SOURCE
                    else "NOASSERTION"
                ),
                "sourceInfo": (
                    "Cargo metadata and Cargo.lock; source files were not analyzed"
                ),
                "comment": canonical_key(package, workspace_root),
                "externalRefs": external_refs(package, workspace_root),
            }
        )
    spdx_packages.sort(key=lambda item: item["SPDXID"])

    workspace_members = sorted(set(metadata["workspace_members"]))
    relationships: set[tuple[str, str, str]] = {
        ("SPDXRef-DOCUMENT", "DESCRIBES", ids[member])
        for member in workspace_members
        if member in ids
    }
    for node in metadata.get("resolve", {}).get("nodes", []):
        source_id = ids.get(node["id"])
        if source_id is None:
            continue
        for dependency_id in node.get("dependencies", []):
            target_id = ids.get(dependency_id)
            if target_id is not None:
                relationships.add((source_id, "DEPENDS_ON", target_id))

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": workspace_name,
        "documentNamespace": (
            "urn:spdx:p2p-messenger:"
            f"{quote(workspace_name, safe='')}:{lockfile_sha256}"
        ),
        "creationInfo": {
            "created": CREATED,
            "creators": [
                "Organization: p2p-messenger",
                "Tool: scripts/generate_sbom.py",
            ],
            "comment": (
                "Deterministic SBOM from cargo metadata --locked. "
                f"Cargo.lock SHA-256: {lockfile_sha256}. "
                "Creation time is fixed for reproducibility."
            ),
        },
        "documentDescribes": sorted(
            ids[member] for member in workspace_members if member in ids
        ),
        "packages": spdx_packages,
        "relationships": [
            {
                "spdxElementId": source,
                "relationshipType": relationship,
                "relatedSpdxElement": target,
            }
            for source, relationship, target in sorted(relationships)
        ],
    }


def validate(document: dict[str, Any], workspace_root: Path) -> None:
    """Fail closed on duplicate IDs, dangling endpoints, or local path leaks."""
    package_ids = [package["SPDXID"] for package in document["packages"]]
    if len(package_ids) != len(set(package_ids)):
        raise ValueError("duplicate SPDX identifiers")
    known = {"SPDXRef-DOCUMENT", *package_ids}
    for relationship in document["relationships"]:
        if relationship["spdxElementId"] not in known:
            raise ValueError("relationship has an unknown source")
        if relationship["relatedSpdxElement"] not in known:
            raise ValueError("relationship has an unknown target")
    serialized = json.dumps(document, sort_keys=True, indent=2)
    if normalize_path_text(str(workspace_root)) in serialized:
        raise ValueError("document leaked an absolute workspace path")
    for package in document["packages"]:
        for reference in package["externalRefs"]:
            if reference["referenceType"] == "cargo-manifest":
                locator = reference["referenceLocator"]
                if locator.startswith("/") or ":" in locator[:2]:
                    raise ValueError("absolute manifest path leaked into SBOM")


def serialize(document: dict[str, Any]) -> str:
    """Serialize deterministically with a trailing newline."""
    return json.dumps(document, sort_keys=True, indent=2) + "\n"


def run_self_tests() -> None:
    root = Path("/workspace/example")
    metadata = {
        "workspace_root": str(root),
        "workspace_members": ["path:local#demo@0.1.0"],
        "packages": [
            {
                "id": "path:local#demo@0.1.0",
                "name": "demo",
                "version": "0.1.0",
                "source": None,
                "license": "MIT/Apache-2.0",
                "manifest_path": str(root / "crates" / "demo" / "Cargo.toml"),
            },
            {
                "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
                "name": "serde",
                "version": "1.0.0",
                "source": CRATES_IO_SOURCE,
                "license": "MIT OR Apache-2.0",
                "manifest_path": "/registry/serde-1.0.0/Cargo.toml",
            },
        ],
        "resolve": {
            "nodes": [
                {
                    "id": "path:local#demo@0.1.0",
                    "dependencies": [
                        "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0"
                    ],
                }
            ]
        },
    }
    document = build_document(metadata, "example", "0" * 64)
    validate(document, root)

    licenses = {item["licenseDeclared"] for item in document["packages"]}
    if "MIT OR Apache-2.0" not in licenses:
        raise AssertionError("slash license was not normalized")
    if any("/ " in value for value in licenses):
        raise AssertionError("deprecated slash separator remains")
    if any("workspace/example" in item["comment"] for item in document["packages"]):
        raise AssertionError("absolute local path leaked into a package comment")
    if len(document["relationships"]) != 2:
        raise AssertionError("expected one DESCRIBES and one DEPENDS_ON relationship")
    if serialize(document) != serialize(build_document(metadata, "example", "0" * 64)):
        raise AssertionError("document serialization is not deterministic")


def cargo_metadata(manifest_path: Path) -> dict[str, Any]:
    """Read locked Cargo metadata without modifying the lockfile."""
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--manifest-path",
            str(manifest_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "unknown cargo metadata failure"
        raise RuntimeError(f"cargo metadata failed: {detail}")
    return json.loads(result.stdout)


def read_lockfile_digest(manifest_path: Path) -> str:
    lockfile = manifest_path.parent / "Cargo.lock"
    if not lockfile.is_file():
        raise FileNotFoundError(f"missing locked dependency graph: {lockfile}")
    return hashlib.sha256(lockfile.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest-path",
        default="Cargo.toml",
        help="Cargo manifest whose locked graph is described",
    )
    parser.add_argument(
        "--workspace-name",
        required=True,
        help="stable SBOM document name, such as root or fuzz",
    )
    parser.add_argument(
        "--output", required=True, help="path for the generated SPDX JSON file"
    )
    args = parser.parse_args(argv)

    try:
        run_self_tests()
        manifest = Path(args.manifest_path)
        if not manifest.is_file():
            raise FileNotFoundError(f"missing manifest: {manifest}")
        metadata = cargo_metadata(manifest)
        digest = read_lockfile_digest(manifest)
        document = build_document(metadata, args.workspace_name, digest)
        validate(document, Path(normalize_path_text(str(metadata["workspace_root"]))))
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(serialize(document), encoding="utf-8")
    except (AssertionError, FileNotFoundError, RuntimeError, ValueError) as error:
        print(f"SBOM generation failed: {error}", file=sys.stderr)
        return 1

    print(
        f"Generated {output}: {len(document['packages'])} packages, "
        f"{len(document['relationships'])} relationships, "
        f"Cargo.lock SHA-256 {digest}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

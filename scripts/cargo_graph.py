"""Select the native normal/build Cargo dependency graph for an exact checkout."""

from pathlib import Path
import tomllib


def package_id(name: str, version: str) -> str:
    return f"SPDXRef-Package-{name}-{version}"


def selected_graph(metadata: dict, locked: list[dict], root: Path) -> tuple[set[tuple[str, str]], set[tuple[str, str]], str]:
    if not isinstance(metadata, dict) or Path(metadata.get("workspace_root", "")).resolve() != root.resolve():
        raise ValueError("Cargo metadata belongs to another workspace")
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict) or not isinstance(resolve.get("nodes"), list):
        raise ValueError("Cargo metadata lacks a resolved dependency graph")
    root_id = resolve.get("root")
    if not isinstance(root_id, str) or metadata.get("workspace_members") != [root_id]:
        raise ValueError("Cargo metadata has no unique root package")
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in resolve["nodes"]}
    if len(packages) != len(metadata["packages"]) or len(nodes) != len(resolve["nodes"]) or root_id not in nodes or root_id not in packages:
        raise ValueError("Cargo metadata has duplicate or missing package IDs")
    root_package = packages[root_id]
    manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["package"]
    if (root_package["name"], root_package["version"]) != (manifest["name"], manifest["version"]):
        raise ValueError("Cargo metadata root differs from Cargo.toml")
    if Path(root_package["manifest_path"]).resolve() != (root / "Cargo.toml").resolve():
        raise ValueError("Cargo metadata root manifest differs from checkout")
    if not any(target.get("name") == "codex-autoapprover" and "bin" in target.get("kind", [])
               for target in root_package["targets"]):
        raise ValueError("Cargo metadata lacks the consumer binary target")
    locked_by_key = {(package["name"], package["version"]): package for package in locked}
    if len(locked_by_key) != len(locked):
        raise ValueError("Cargo.lock has ambiguous package identities")
    seen, edges, pending = set(), set(), [root_id]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        if current not in packages or current not in nodes:
            raise ValueError("resolved package absent from Cargo metadata")
        package = packages[current]
        key = package["name"], package["version"]
        if key not in locked_by_key or package.get("source") != locked_by_key[key].get("source"):
            raise ValueError("resolved package differs from Cargo.lock")
        seen.add(current)
        for dependency in nodes[current]["deps"]:
            kinds = dependency.get("dep_kinds")
            if not isinstance(kinds, list) or not kinds or any(
                    not isinstance(kind, dict) or kind.get("kind") not in (None, "build", "dev")
                    for kind in kinds):
                raise ValueError("unexpected Cargo dependency kind")
            if any(kind["kind"] in (None, "build") for kind in kinds):
                target_id = dependency["pkg"]
                if target_id not in packages:
                    raise ValueError("Cargo dependency package is missing")
                edges.add((current, target_id))
                pending.append(target_id)
    keys = {(packages[identifier]["name"], packages[identifier]["version"]) for identifier in seen}
    if len(keys) != len(seen):
        raise ValueError("selected packages have ambiguous SPDX identities")
    relationships = {(package_id(packages[parent]["name"], packages[parent]["version"]),
                      package_id(packages[child]["name"], packages[child]["version"]))
                     for parent, child in edges}
    return keys, relationships, package_id(root_package["name"], root_package["version"])

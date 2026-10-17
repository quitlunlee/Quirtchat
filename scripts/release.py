#!/usr/bin/env python3
"""Build distribution archives from explicit inputs; never bundle a profile or checkout."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "x86_64-pc-windows-msvc": ("pe", 0x8664),
    "x86_64-unknown-linux-musl": ("elf", 62),
    "aarch64-unknown-linux-musl": ("elf", 183),
    "x86_64-apple-darwin": ("macho", 0x01000007),
    "aarch64-apple-darwin": ("macho", 0x0100000C),
}
LICENSE_NAME = re.compile(r"^(licen[cs]e|copying|copyright|notice|unlicense|authors)([._-].*)?$", re.I)


def version(tag: str | None = None) -> str:
    value = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", value):
        raise ValueError("unsupported release version")
    if tag is not None and tag != f"v{value}":
        raise ValueError(f"tag must match Cargo.toml: expected v{value}")
    return value


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(args: list[str], *, cwd: Path = ROOT, timeout: int = 90) -> str:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} failed ({result.returncode}): {result.stderr[-2000:]}")
    return result.stdout.strip()


def validate_binary(path: Path, target: str) -> None:
    """Reject mislabeled architectures, text placeholders and another OS's executable."""
    expected, machine = TARGETS[target]
    with path.open("rb") as stream:
        header = stream.read(64)
        if expected == "pe":
            if len(header) < 64 or header[:2] != b"MZ":
                raise ValueError("expected a Windows PE executable")
            offset = struct.unpack_from("<I", header, 60)[0]
            if offset > path.stat().st_size - 6:
                raise ValueError("invalid PE header offset")
            stream.seek(offset)
            pe = stream.read(6)
            if pe[:4] != b"PE\0\0" or struct.unpack_from("<H", pe, 4)[0] != machine:
                raise ValueError("wrong PE architecture")
        elif expected == "elf":
            if len(header) < 20 or header[:6] != b"\x7fELF\x02\x01":
                raise ValueError("expected a 64-bit little-endian ELF executable")
            if struct.unpack_from("<H", header, 18)[0] != machine:
                raise ValueError("wrong ELF architecture")
        else:
            if len(header) < 8 or header[:4] != b"\xcf\xfa\xed\xfe":
                raise ValueError("expected a thin 64-bit Mach-O executable")
            if struct.unpack_from("<I", header, 4)[0] != machine:
                raise ValueError("wrong Mach-O architecture")


def smoke(binary: Path) -> None:
    binary = binary.resolve(strict=True)
    expected = f"clichat {version()}"
    if command([str(binary), "--version"]) != expected:
        raise ValueError(f"binary version does not match {expected}")
    command([str(binary), "--help"])
    # Nothing is written to the user's real profile. No networking is needed.
    with tempfile.TemporaryDirectory(prefix="clichat-release-smoke-") as temporary:
        area = Path(temporary)
        password = area / "password"
        wrong = area / "wrong-password"
        for file in (password, wrong):
            file.write_text(secrets.token_hex(32), encoding="utf-8")
            file.chmod(0o600)
        profile = area / "profile"
        common = [str(binary), "--data-dir", str(profile), "--password-file", str(password)]
        command([*common, "init", "--name", "Release测试"], cwd=area)
        command([*common, "config", "cache", "off"], cwd=area)
        status = command([*common, "status"], cwd=area)
        if "Release测试" not in status or "Public cache participation: false" not in status:
            raise ValueError("profile did not survive reopen with the saved configuration")
        denied = subprocess.run([str(binary), "--data-dir", str(profile), "--password-file", str(wrong), "status"],
                                cwd=area, capture_output=True, timeout=90)
        if denied.returncode == 0:
            raise ValueError("wrong profile password was accepted")
        with (profile / "profile.db").open("rb") as database:
            if database.read(16) == b"SQLite format 3\0":
                raise ValueError("profile database is not encrypted")


def license_files(crate: Path, explicit: str | None) -> list[Path]:
    selected: set[Path] = set()
    for directory, folders, files in os.walk(crate):
        folders[:] = [folder for folder in folders if folder not in (".git", "target") and not (Path(directory) / folder).is_symlink()]
        folder = Path(directory)
        in_licenses = any(part.lower() in ("license", "licenses", "licence", "licences") for part in folder.relative_to(crate).parts)
        for name in files:
            path = folder / name
            if (in_licenses or LICENSE_NAME.fullmatch(name)) and not path.is_symlink():
                selected.add(path)
    if explicit:
        path = (crate / explicit).resolve(strict=True)
        if not path.is_relative_to(crate.resolve()):
            raise ValueError("license_file escapes its dependency directory")
        selected.add(path)
    return sorted(selected)


def collect_licenses(metadata: dict, destination: Path) -> None:
    active = {node["id"] for node in metadata["resolve"]["nodes"]}
    own = metadata["resolve"]["root"]
    if not own:
        raise ValueError("cargo metadata must identify the CLIChat package")
    inventory = []
    missing = []
    source_index = ROOT / "packaging" / "license-sources.json"
    supplements = json.loads(source_index.read_text(encoding="utf-8")) if source_index.exists() else []
    supplements = {(item["name"], item["version"]): item["files"] for item in supplements}
    for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
        if package["id"] not in active or package["id"] == own:
            continue
        crate = Path(package["manifest_path"]).resolve().parent
        key = f'{package["name"]}-{package["version"]}'
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", key):
            raise ValueError("unsafe dependency name")
        files = license_files(crate, package.get("license_file"))
        paths = []
        for source in files:
            if source.stat().st_size > 2 * 1024 * 1024:
                raise ValueError(f"unexpectedly large license file in {key}")
            relative = source.relative_to(crate)
            output = destination / key / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, output)
            paths.append(relative.as_posix())
        provenance = []
        for entry in supplements.get((package["name"], package["version"]), []):
            source = (ROOT / "packaging" / entry["path"]).resolve(strict=True)
            if not source.is_relative_to((ROOT / "packaging" / "licenses").resolve()) or digest(source) != entry["sha256"]:
                raise ValueError(f"invalid pinned license supplement: {key}")
            # The relative source path keeps separately named upstream notices distinct.
            relative = Path("upstream") / source.relative_to(ROOT / "packaging" / "licenses")
            output = destination / key / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, output)
            paths.append(relative.as_posix())
            provenance.append({"file": relative.as_posix(), "url": entry["url"], "sha256": entry["sha256"]})
        if not paths:
            missing.append(key)
            continue
        inventory.append({"name": package["name"], "version": package["version"],
                          "license": package.get("license"), "source": package.get("source"),
                          "repository": package.get("repository"), "files": paths, "upstream_supplements": provenance})
        if package.get("license") == "MPL-2.0" or package["name"] == "enum-assoc":
            # Ship the exact published source for file-level copyleft crates.
            # For enum-assoc retain its original license declaration/notice context.
            source_destination = destination.parent / "THIRD_PARTY_SOURCES" / key
            for directory, folders, names in os.walk(crate):
                folders[:] = [folder for folder in folders if folder not in (".git", "target") and not (Path(directory) / folder).is_symlink()]
                for name in names:
                    source = Path(directory) / name
                    if source.is_symlink() or name == ".cargo-ok":
                        continue
                    output = source_destination / source.relative_to(crate)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, output)
            inventory[-1]["source_included"] = f"THIRD_PARTY_SOURCES/{key}"
    if missing:
        raise ValueError("dependency license texts missing; review before distribution: " + ", ".join(missing))
    # Native SQLCipher and OpenSSL notices are below these crates' top-level licenses.
    for prefix, required in (("libsqlite3-sys-", "sqlcipher/LICENSE"), ("openssl-src-", "openssl/LICENSE.txt")):
        if not any(item["name"].startswith(prefix.rstrip("-")) and required in item["files"] for item in inventory):
            raise ValueError(f"missing bundled native license: {required}")
    (destination / "DEPENDENCIES.json").write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (destination.parent / "SOURCE_ACCESS.txt").write_text(
        "Dependencies and their declared licenses are listed in THIRD_PARTY_LICENSES/DEPENDENCIES.json.\n"
        "Exact published sources for MPL-2.0 dependencies are included in THIRD_PARTY_SOURCES.\n"
        "These dependency sources are unmodified; their licenses and copyright notices remain applicable.\n"
        "Supplemental upstream license texts have pinned source URLs and SHA-256 hashes in DEPENDENCIES.json.\n"
        "enum-assoc and the hpke-rs packages omit standalone license files in their published sources.\n"
        "For these packages the bundle includes original license declarations, unmodified sources,\n"
        "and canonical SPDX license texts. Canonical texts are not package-specific copyright notices;\n"
        "their template placeholders are preserved, and no copyright attribution has been invented.\n"
        "Rust standard-library and compiler/runtime notices are included in RUNTIME_LICENSES.\n"
        "RUNTIME_LICENSES/NOTICES.json records the selected Rust release, source commit and file hashes.\n"
        "Other registry package sources are available at https://crates.io/crates/<name>/<version>/download.\n",
        encoding="utf-8")


def collect_runtime_notices(target: str, destination: Path, rust_sysroot: Path | None = None) -> None:
    """Keep standard-library notices from the compiler actually used for packaging."""
    if target not in TARGETS:
        raise ValueError("unsupported runtime notice target")
    if rust_sysroot is None:
        rust_sysroot = Path(command(["rustc", "--print", "sysroot"]))
    rust_sysroot = rust_sysroot.resolve(strict=True)
    compiler = rust_sysroot / "bin" / ("rustc.exe" if os.name == "nt" else "rustc")
    compiler_info = command([str(compiler), "--version", "--verbose"])
    details = dict(line.split(": ", 1) for line in compiler_info.splitlines() if ": " in line)
    pinned = json.loads((ROOT / "packaging" / "runtime-sources.json").read_text(encoding="utf-8"))
    channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]
    if (details.get("release") != channel or pinned["rust_release"] != channel
            or details.get("commit-hash") != pinned["rust_commit"]):
        raise ValueError("Rust toolchain differs from the pinned runtime notices; review runtime-sources.json")
    if not (rust_sysroot / "lib" / "rustlib" / target / "lib").is_dir():
        raise ValueError(f"Rust target is not installed in the selected sysroot: {target}")

    copied = []

    def copy_notice(source: Path, relative: Path, origin: dict, allowed_root: Path) -> None:
        resolved = source.resolve(strict=True)
        if source.is_symlink() or not resolved.is_relative_to(allowed_root.resolve()) or not resolved.is_file():
            raise ValueError("runtime notice escapes its source directory or is not a regular file")
        if not 0 < resolved.stat().st_size <= 32 * 1024 * 1024:
            raise ValueError("unexpected runtime notice size")
        expected = origin.get("sha256")
        actual = digest(resolved)
        if expected is not None and expected != actual:
            raise ValueError(f"invalid pinned runtime notice: {relative.as_posix()}")
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(resolved, output)
        copied.append({"file": relative.as_posix(), **origin, "sha256": actual})

    documentation = rust_sysroot / "share" / "doc" / "rust"
    copy_notice(documentation / "COPYRIGHT-library.html", Path("rust/COPYRIGHT-library.html"),
                {"sysroot_file": "share/doc/rust/COPYRIGHT-library.html"}, rust_sysroot)
    license_directory = documentation / "licenses"
    for required in ("MIT.txt", "Apache-2.0.txt", "Unicode-3.0.txt"):
        if not (license_directory / required).is_file():
            raise ValueError(f"Rust sysroot is missing a required license: {required}")
    for source in sorted(license_directory.glob("*.txt")):
        copy_notice(source, Path("rust/licenses") / source.name,
                    {"sysroot_file": f"share/doc/rust/licenses/{source.name}"}, rust_sysroot)

    included_components = set()
    for entry in pinned["files"]:
        if target not in entry["targets"]:
            continue
        source = ROOT / "packaging" / entry["path"]
        allowed = ROOT / "packaging" / "licenses"
        resolved = source.resolve(strict=True)
        if not resolved.is_relative_to(allowed.resolve()):
            raise ValueError("pinned runtime notice escapes packaging/licenses")
        relative = Path("upstream") / resolved.relative_to(allowed.resolve())
        copy_notice(source, relative, {"component": entry["component"], "url": entry["url"],
                                     "sha256": entry["sha256"]}, allowed)
        included_components.add(entry["component"])
    required_components = {"compiler-builtins", "libm"}
    if target.endswith("linux-musl"):
        required_components.update({"musl 1.2.5 (with Rust toolchain patches)", "LLVM libunwind"})
    if not required_components <= included_components:
        raise ValueError("missing pinned compiler or static runtime license")
    inventory = {"target": target, "rust_release": details["release"], "rust_commit": details["commit-hash"],
                 "source_evidence": pinned["source_evidence"], "files": copied}
    (destination / "NOTICES.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")


def package(target: str, binary: Path, metadata_path: Path, out_dir: Path,
            rust_sysroot: Path | None = None) -> Path:
    release_version = version()
    binary = binary.resolve(strict=True)
    validate_binary(binary, target)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
    root_package = next((item for item in metadata["packages"] if item["id"] == metadata["resolve"]["root"]), None)
    if not root_package or root_package["name"] != "clichat" or root_package["version"] != release_version:
        raise ValueError("metadata does not match this release")
    if command([str(binary), "--version"]) != f"clichat {release_version}":
        raise ValueError("binary version mismatch")
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"clichat-{release_version}-{target}"
    windows = target.endswith("windows-msvc")
    archive = out_dir / (stem + (".zip" if windows else ".tar.gz"))
    if archive.exists() or archive.with_name(archive.name + ".sha256").exists():
        raise ValueError(f"release output already exists: {archive.name}; use a new output directory")
    try:
        revision = command(["git", "rev-parse", "HEAD"])
        dirty = bool(command(["git", "status", "--porcelain"]))
    except (RuntimeError, FileNotFoundError):
        revision, dirty = None, True
    with tempfile.TemporaryDirectory(prefix="clichat-package-") as temporary:
        stage = Path(temporary) / stem
        stage.mkdir()
        executable = stage / ("clichat.exe" if windows else "clichat")
        shutil.copyfile(binary, executable)
        executable.chmod(0o755)
        # Explicit allowlist: no databases, passwords, invitation files, tools or logs.
        for name in ("README.md", "LICENSE-MIT", "LICENSE-APACHE"):
            shutil.copyfile(ROOT / name, stage / name)
        collect_licenses(metadata, stage / "THIRD_PARTY_LICENSES")
        collect_runtime_notices(target, stage / "RUNTIME_LICENSES", rust_sysroot)
        instructions = ("Windows: open this folder in Windows Terminal or PowerShell.\n"
                        ".\\clichat.exe init --name YourName\n.\\clichat.exe chat\n" if windows else
                        "Linux/macOS: open a terminal in this directory.\n"
                        "chmod +x clichat\n./clichat init --name YourName\n./clichat chat\n\n"
                        "Optional user-only installation:\nmkdir -p \"$HOME/.local/bin\"\n"
                        "install -m 755 clichat \"$HOME/.local/bin/clichat\"\n"
                        "Add $HOME/.local/bin to PATH if needed.\n")
        instructions += ("\nmpv is optional for in-terminal audio/video playback.\n"
                         "Read README.md for invitation exchange, proxy setup and security limits.\n"
                         "This is an unaudited prototype. Public-release code signing/notarization is not configured.\n")
        (stage / "INSTALL.txt").write_text(instructions, encoding="utf-8")
        manifest = {"name": "clichat", "version": release_version, "target": target,
                    "source_commit": revision, "source_dirty": dirty,
                    "binary_sha256": digest(executable), "code_signing": "ad-hoc only" if "apple" in target else "unsigned",
                    "files": {path.relative_to(stage).as_posix(): digest(path) for path in sorted(stage.rglob("*")) if path.is_file()}}
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        pending = archive.with_name(archive.name + ".part")
        try:
            if windows:
                with zipfile.ZipFile(pending, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
                    for path in sorted(stage.rglob("*")):
                        if path.is_file():
                            bundle.write(path, path.relative_to(stage.parent).as_posix())
            else:
                with tarfile.open(pending, "w:gz", compresslevel=9) as bundle:
                    bundle.add(stage, arcname=stem)
            pending.replace(archive)
        finally:
            pending.unlink(missing_ok=True)
    archive.with_name(archive.name + ".sha256").write_text(f"{digest(archive)}  {archive.name}\n", encoding="ascii")
    return archive


def checksums(directory: Path, require_all: bool) -> Path:
    expected = {f"clichat-{version()}-{target}" + (".zip" if target.endswith("windows-msvc") else ".tar.gz") for target in TARGETS}
    archives = sorted([*directory.glob("*.zip"), *directory.glob("*.tar.gz")])
    found = {path.name for path in archives}
    if not found or not found <= expected or (require_all and found != expected):
        raise ValueError("release archive set is empty, unexpected, or missing required targets")
    lines = []
    for archive in archives:
        line = f"{digest(archive)}  {archive.name}\n"
        if archive.with_name(archive.name + ".sha256").read_text(encoding="ascii") != line:
            raise ValueError(f"checksum mismatch: {archive.name}")
        lines.append(line)
    output = directory / "SHA256SUMS"
    output.write_text("".join(lines), encoding="ascii")
    return output


def main() -> None:
    # Windows redirected output may use an ANSI code page that cannot represent
    # the workspace path. Emit UTF-8 consistently with our subprocess capture.
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    get_version = commands.add_parser("version")
    get_version.add_argument("--tag")
    check = commands.add_parser("smoke")
    check.add_argument("--binary", type=Path, required=True)
    pack = commands.add_parser("package")
    pack.add_argument("--target", choices=TARGETS, required=True)
    pack.add_argument("--binary", type=Path, required=True)
    pack.add_argument("--metadata", type=Path, required=True)
    pack.add_argument("--out-dir", type=Path, default=ROOT / "dist" / "releases")
    pack.add_argument("--rust-sysroot", type=Path,
                      help="Rust sysroot used to build the binary (defaults to rustc --print sysroot)")
    sums = commands.add_parser("checksums")
    sums.add_argument("--dir", type=Path, required=True)
    sums.add_argument("--require-all", action="store_true")
    args = parser.parse_args()
    try:
        if args.operation == "version":
            print(version(args.tag))
        elif args.operation == "smoke":
            smoke(args.binary)
            print("Release smoke passed: version, encrypted profile, reopen, configuration, wrong-password rejection.")
        elif args.operation == "package":
            print(package(args.target, args.binary, args.metadata, args.out_dir, args.rust_sysroot))
        else:
            print(checksums(args.dir, args.require_all))
    except (OSError, ValueError, RuntimeError, KeyError, StopIteration, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"release: {error}\n")


if __name__ == "__main__":
    main()

"""Checks for release labeling, artifact integrity and accidental profile disclosure."""
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import release


def runtime_fixture(root):
    """A minimal compiler installation with unrelated private files beside it."""
    sysroot = root / "toolchain"
    documentation = sysroot / "share/doc/rust"
    licenses = documentation / "licenses"
    licenses.mkdir(parents=True)
    (documentation / "COPYRIGHT-library.html").write_bytes(b"standard library copyright")
    for name in ("MIT.txt", "Apache-2.0.txt", "Unicode-3.0.txt"):
        (licenses / name).write_bytes(name.encode("ascii"))
    (documentation / "private.txt").write_bytes(b"PRIVATE_SENTINEL")
    (sysroot / "secret.key").write_bytes(b"PRIVATE_SENTINEL")
    for target in release.TARGETS:
        (sysroot / "lib/rustlib" / target / "lib").mkdir(parents=True)
    (root / "rust-toolchain.toml").write_text('[toolchain]\nchannel="1.99.1"\n', encoding="utf-8")
    all_targets = list(release.TARGETS)
    musl_targets = [target for target in all_targets if target.endswith("linux-musl")]
    pinned = {"rust_release": "1.99.1", "rust_commit": "a" * 40, "source_evidence": [], "files": []}
    for index, (name, targets) in enumerate((("compiler-builtins", all_targets), ("libm", all_targets),
                                           ("musl 1.2.5 (with Rust toolchain patches)", musl_targets),
                                           ("LLVM libunwind", musl_targets))):
        relative = f"licenses/runtime-{index}/LICENSE"
        source = root / "packaging" / relative
        source.parent.mkdir(parents=True)
        source.write_text(name, encoding="utf-8")
        pinned["files"].append({"component": name, "targets": targets, "path": relative,
                                "url": "https://example.invalid/pinned/LICENSE", "sha256": release.digest(source)})
    (root / "packaging/runtime-sources.json").write_text(json.dumps(pinned), encoding="utf-8")
    return sysroot, pinned


RUST_VERSION = "rustc 1.99.1 (aaaaaaaaa)\nrelease: 1.99.1\ncommit-hash: " + "a" * 40


class ReleaseTests(unittest.TestCase):
    def test_version_must_match_tag(self):
        self.assertEqual(release.version("v" + release.version()), release.version())
        for tag in ("v999.0.0", "0.1.0", "v0.1.0/../profile.db"):
            with self.assertRaises(ValueError):
                release.version(tag)

    def test_architecture_validation_rejects_mislabeling(self):
        with tempfile.TemporaryDirectory() as area:
            binary = Path(area) / "binary"
            header = bytearray(64)
            header[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", header, 18, 62)
            binary.write_bytes(header)
            release.validate_binary(binary, "x86_64-unknown-linux-musl")
            for target in ("aarch64-unknown-linux-musl", "x86_64-pc-windows-msvc", "aarch64-apple-darwin"):
                with self.assertRaises(ValueError):
                    release.validate_binary(binary, target)

    def test_checksums_reject_tampering_and_incomplete_release(self):
        with tempfile.TemporaryDirectory() as area:
            directory = Path(area)
            archive = directory / f"clichat-{release.version()}-x86_64-pc-windows-msvc.zip"
            archive.write_bytes(b"archive")
            archive.with_name(archive.name + ".sha256").write_text(f"{release.digest(archive)}  {archive.name}\n", encoding="ascii")
            release.checksums(directory, False)
            with self.assertRaises(ValueError):
                release.checksums(directory, True)
            archive.write_bytes(b"altered")
            with self.assertRaises(ValueError):
                release.checksums(directory, False)

    def test_package_allowlist_excludes_profile_credentials_and_tools(self):
        with tempfile.TemporaryDirectory() as area:
            root = Path(area)
            (root / "Cargo.toml").write_text('[package]\nname="clichat"\nversion="0.1.0"\n', encoding="utf-8")
            for name in ("README.md", "LICENSE-MIT", "LICENSE-APACHE"):
                (root / name).write_text("public documentation", encoding="utf-8")
            for name in ("profile.db", "password.txt", "alice.invite", ".env", "FILE"):
                (root / name).write_text("PRIVATE_SENTINEL", encoding="utf-8")
            binary = root / "clichat.exe"
            header = bytearray(70)
            header[:2] = b"MZ"
            struct.pack_into("<I", header, 60, 64)
            header[64:68] = b"PE\0\0"
            struct.pack_into("<H", header, 68, 0x8664)
            binary.write_bytes(header)
            metadata = root / "metadata.json"
            metadata.write_text(json.dumps({"resolve": {"root": "self"}, "packages": [{"id": "self", "name": "clichat", "version": "0.1.0"}]}), encoding="utf-8")
            sysroot, _ = runtime_fixture(root)

            def command(args):
                if "--verbose" in args:
                    return RUST_VERSION
                return "clichat 0.1.0" if "--version" in args else "test-commit"

            with patch.object(release, "ROOT", root), patch.object(release, "command", command), patch.object(release, "collect_licenses"):
                archive = release.package("x86_64-pc-windows-msvc", binary, metadata, root / "output", sysroot)
                with zipfile.ZipFile(archive) as bundle:
                    names = {Path(name).name for name in bundle.namelist()}
                    self.assertEqual(names, {"clichat.exe", "README.md", "LICENSE-MIT", "LICENSE-APACHE", "INSTALL.txt", "manifest.json",
                                             "COPYRIGHT-library.html", "MIT.txt", "Apache-2.0.txt", "Unicode-3.0.txt", "LICENSE", "NOTICES.json"})
                    for name in bundle.namelist():
                        self.assertNotIn(b"PRIVATE_SENTINEL", bundle.read(name))
                    manifest = json.loads(bundle.read(next(name for name in bundle.namelist() if name.endswith("manifest.json"))))
                    self.assertEqual(manifest["binary_sha256"], release.digest(binary))
                    self.assertIn("RUNTIME_LICENSES/NOTICES.json", manifest["files"])
                with self.assertRaises(ValueError):
                    release.package("x86_64-pc-windows-msvc", binary, metadata, root / "output", sysroot)

    def test_runtime_notices_cover_each_target_and_preserve_bytes(self):
        with tempfile.TemporaryDirectory() as area:
            root = Path(area)
            sysroot, _ = runtime_fixture(root)
            with patch.object(release, "ROOT", root), patch.object(release, "command", return_value=RUST_VERSION):
                for target in release.TARGETS:
                    output = root / target
                    release.collect_runtime_notices(target, output, sysroot)
                    inventory = json.loads((output / "NOTICES.json").read_text(encoding="utf-8"))
                    self.assertEqual(inventory["rust_commit"], "a" * 40)
                    components = {entry.get("component") for entry in inventory["files"]}
                    self.assertEqual("LLVM libunwind" in components, target.endswith("linux-musl"))
                    self.assertIn("compiler-builtins", components)
                    for entry in inventory["files"]:
                        source = output / entry["file"]
                        self.assertEqual(release.digest(source), entry["sha256"])
                        self.assertNotIn(b"PRIVATE_SENTINEL", source.read_bytes())
                    self.assertNotIn(str(sysroot), (output / "NOTICES.json").read_text())

    def test_runtime_notices_default_to_rustc_sysroot(self):
        with tempfile.TemporaryDirectory() as area:
            root = Path(area)
            sysroot, _ = runtime_fixture(root)
            def command(args):
                return str(sysroot) if args == ["rustc", "--print", "sysroot"] else RUST_VERSION
            with patch.object(release, "ROOT", root), patch.object(release, "command", side_effect=command) as run:
                release.collect_runtime_notices("x86_64-pc-windows-msvc", root / "output")
                run.assert_any_call(["rustc", "--print", "sysroot"])

    def test_runtime_notices_reject_wrong_compiler_and_missing_target(self):
        with tempfile.TemporaryDirectory() as area:
            root = Path(area)
            sysroot, _ = runtime_fixture(root)
            with patch.object(release, "ROOT", root):
                for wrong in (RUST_VERSION.replace("1.99.1", "1.99.2"), RUST_VERSION.replace("a" * 40, "b" * 40)):
                    with patch.object(release, "command", return_value=wrong), self.assertRaisesRegex(ValueError, "toolchain differs"):
                        release.collect_runtime_notices("x86_64-pc-windows-msvc", root / "output", sysroot)
                (sysroot / "lib/rustlib/x86_64-pc-windows-msvc/lib").rmdir()
                with patch.object(release, "command", return_value=RUST_VERSION), self.assertRaisesRegex(ValueError, "target is not installed"):
                    release.collect_runtime_notices("x86_64-pc-windows-msvc", root / "output", sysroot)

    def test_runtime_notices_reject_missing_or_tampered_licenses(self):
        with tempfile.TemporaryDirectory() as area:
            root = Path(area)
            sysroot, pinned = runtime_fixture(root)
            with patch.object(release, "ROOT", root), patch.object(release, "command", return_value=RUST_VERSION):
                required = sysroot / "share/doc/rust/licenses/MIT.txt"
                original = required.read_bytes()
                required.unlink()
                with self.assertRaisesRegex(ValueError, "missing a required license"):
                    release.collect_runtime_notices("x86_64-pc-windows-msvc", root / "missing", sysroot)
                required.write_bytes(original)
                source = root / "packaging" / pinned["files"][0]["path"]
                source.write_bytes(b"altered")
                with self.assertRaisesRegex(ValueError, "invalid pinned runtime notice"):
                    release.collect_runtime_notices("x86_64-pc-windows-msvc", root / "altered", sysroot)

    def test_runtime_notices_reject_supplement_outside_allowlist(self):
        with tempfile.TemporaryDirectory() as area:
            root = Path(area)
            sysroot, pinned = runtime_fixture(root)
            pinned["files"][0]["path"] = "../toolchain/secret.key"
            pinned["files"][0]["sha256"] = release.digest(sysroot / "secret.key")
            (root / "packaging/runtime-sources.json").write_text(json.dumps(pinned), encoding="utf-8")
            with patch.object(release, "ROOT", root), patch.object(release, "command", return_value=RUST_VERSION):
                with self.assertRaisesRegex(ValueError, "escapes packaging/licenses"):
                    release.collect_runtime_notices("x86_64-pc-windows-msvc", root / "output", sysroot)


if __name__ == "__main__":
    unittest.main()

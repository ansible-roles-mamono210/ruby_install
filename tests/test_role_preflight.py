"""Controller input resolution, target state precedence and changes to protected files."""
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "filter_plugins"))
sys.path.insert(0, str(ROOT / "module_utils"))
import ruby_install_inputs as inputs
from ruby_install_preflight import health, state


class Inputs(unittest.TestCase):
    def resolve(self, version="3.4.12", url="", checksum="", prefix="/opt/ruby", workspace="/tmp"):
        return inputs.resolve_inputs(version, url, checksum, prefix, workspace)

    def test_registered_sources(self):
        for version, digest in inputs.CHECKSUMS.items():
            result = self.resolve(version)
            self.assertEqual(result["sha256"], digest)
            self.assertEqual(result["url"], "https://cache.ruby-lang.org/pub/ruby/{}/ruby-{}.tar.gz".format(
                version.rsplit(".", 1)[0], version))

    def test_stable_versions_only(self):
        for version in ("3.4", "4.1.0", "4.0.01", "3.4.12-preview1", " 3.4.12", "3.4.12\n", False):
            with self.subTest(version=version):
                self.assertIn("INVALID_INPUT:", self.resolve(version)["error"])

    def test_custom_source_and_unregistered_patch(self):
        digest = "A0" * 32
        for url in ("", "https://example.org/ruby.tgz?key=private", "https://[::1]:444/file"):
            self.assertEqual(self.resolve("4.0.10", url, "sha256:" + digest)["sha256"], digest.lower())
            self.assertIn("INVALID_INPUT:", self.resolve("4.0.10", url)["error"])

    def test_registered_artifact_cannot_override_digest(self):
        for url in ("", self.resolve()["url"], "https://CACHE.RUBY-LANG.ORG.:443/pub/ruby/3.4/./ruby-3.4.12.tar.gz?token=x"):
            self.assertIn("INVALID_INPUT:", self.resolve(url=url, checksum="sha256:" + "0" * 64)["error"])
        self.assertIn("INVALID_INPUT:", self.resolve(url=self.resolve()["url"])["error"])

    def test_bad_urls_are_not_echoed(self):
        for address in ("http://x/private", "https://u:private@x/z", "https://:private",
                        "https://bad host/private", "https:///private", "https://x:bad/private",
                        "https://[::1]suffix/private", "https://x\\private"):
            result = self.resolve(url=address, checksum="sha256:" + "1" * 64)
            self.assertIn("INVALID_INPUT:", result["error"])
            self.assertNotIn("private", str(result))

    def test_bad_digest(self):
        for digest in ("a" * 64, "sha512:" + "0" * 64, "sha256:" + "z" * 64, "sha256:" + "0" * 63, True):
            self.assertIn("INVALID_INPUT:", self.resolve(checksum=digest)["error"])

    def test_paths(self):
        for prefix, work in (("x", "/tmp"), ("/opt/x/../ruby", "/tmp"), ("/opt/r", "/opt/r/x"),
                             ("/opt/r/x", "/opt/r"), ("/opt/r", "tmp"), ("/opt/r", "/opt/r"),
                             ("/usr/local", "/tmp"), ("/opt/\nx", "/tmp")):
            with self.subTest(prefix=prefix, work=work):
                self.assertIn("INVALID_INPUT:", self.resolve(prefix=prefix, workspace=work)["error"])
        result = self.resolve(prefix="//opt//ruby/./", workspace="/opt/ruby-build")
        self.assertEqual(result["prefix"], "/opt/ruby")


@unittest.skipUnless(sys.platform.startswith("linux"), "target filesystem checks require Linux")
class Observations(unittest.TestCase):
    def setUp(self):
        # Use real files/descriptors and inode/mode/time information. Map owner
        # IDs only in this fixture so the same cases run as CI root or a developer.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.prefix = self.root / "ruby"
        self.work = self.root / "workspace"
        self.work.mkdir()
        self.public = self.root / "public"
        self.public.mkdir()
        self.nobody = set()
        self.sep_fs = False
        orig_lstat, orig_fstat = state.lstat, os.fstat
        ancestors = set(self.root.parents)
        def attrs(s, path=None):
            if s is None:
                return None
            mode = s.st_mode
            if path in ancestors:
                mode &= ~0o022
            return SimpleNamespace(st_mode=mode, st_dev=s.st_dev + int(self.sep_fs and path == self.work),
                                   st_uid=1000 if path in self.nobody else 0, st_gid=0,
                                   st_ino=s.st_ino, st_ctime_ns=s.st_ctime_ns)
        for hook in (patch.object(state, "lstat", side_effect=lambda path: attrs(orig_lstat(path), path)),
                     patch.object(os, "fstat", side_effect=lambda fd: attrs(orig_fstat(fd)))):
            hook.start()
            self.addCleanup(hook.stop)
        self.vfs = patch.object(os, "statvfs", return_value=SimpleNamespace(f_flag=0, f_frsize=1, f_bavail=2 * state.GIB))
        self.fs = self.vfs.start()
        self.addCleanup(self.vfs.stop)
        self.probe = Mock()
        self.req = dict(version="3.4.12", prefix=str(self.prefix), workspace=str(self.work),
                        digest=inputs.CHECKSUMS["3.4.12"], documentation=True)

    def inspect(self):
        return state.inspect(self.req, self.probe, str(self.public))

    def stopped(self, reason):
        with self.assertRaisesRegex(state.Stop, "^" + reason + ":"):
            self.inspect()

    def binary(self):
        path = self.prefix / "bin" / "ruby"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"This fixture must not be executed\n")
        path.chmod(0o755)
        return path

    def record(self, **overrides):
        self.prefix.mkdir(exist_ok=True)
        value = state.installation_record(self.req["version"], self.prefix, self.req["digest"],
                                          True, state.jit_settings(self.req["version"]), True)
        value.update(overrides)
        path = self.prefix / state.RECORD
        path.write_text(json.dumps(value))
        path.chmod(0o644)
        return path

    def test_absent_and_empty_prefix_remain_unchanged(self):
        self.assertEqual(self.inspect(), "new_install_allowed")
        self.assertFalse(self.prefix.exists())
        self.prefix.mkdir()
        self.assertEqual(self.inspect(), "new_install_allowed")
        self.assertEqual(list(self.prefix.iterdir()), [])
        self.assertEqual(list(self.work.iterdir()), [])
        self.probe.assert_not_called()

    def test_safe_parent_link_allowed_final_link_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.req["prefix"] = str(alias / self.prefix.name)
        self.assertEqual(self.inspect(), "new_install_allowed")
        self.prefix.symlink_to(self.work, target_is_directory=True)
        self.stopped("UNSAFE_PATH")

    def test_unsafe_prefix_owner_or_mode(self):
        self.prefix.mkdir()
        self.nobody.add(self.prefix)
        self.stopped("UNSAFE_PATH")
        self.nobody.clear()
        self.prefix.chmod(0o777)
        self.stopped("UNSAFE_PATH")

    def test_workspace_checks_only_for_install_candidates(self):
        self.req["workspace"] = str(self.root / "missing")
        self.stopped("WORKSPACE_INVALID")
        self.req["workspace"] = str(self.work)
        self.fs.return_value.f_flag = os.ST_NOEXEC
        self.stopped("WORKSPACE_NOEXEC")
        self.fs.return_value.f_flag = os.ST_RDONLY
        self.stopped("WORKSPACE_INVALID")
        self.fs.return_value.f_flag = 0
        self.fs.return_value.f_bavail -= 1
        self.stopped("INSUFFICIENT_SPACE")

    def test_sticky_workspace_and_resolved_overlap(self):
        self.work.chmod(0o1777)
        self.assertEqual(self.inspect(), "new_install_allowed")
        self.work.chmod(0o777)
        self.stopped("WORKSPACE_INVALID")
        alias = self.root / "alias"
        alias.symlink_to(self.root)
        self.req["workspace"] = str(alias)
        self.stopped("WORKSPACE_INVALID")

    def test_separate_device_prefix_capacity_boundary(self):
        self.sep_fs = True
        def capacity(path):
            return SimpleNamespace(f_flag=0, f_frsize=1, f_bavail=2 * state.GIB if path == self.work else self.space)
        self.fs.side_effect = capacity
        self.space = state.GIB // 2
        self.assertEqual(self.inspect(), "new_install_allowed")
        self.space -= 1
        self.stopped("INSUFFICIENT_SPACE")

    def test_unrecorded_ruby_is_preserved_and_never_run(self):
        path = self.binary()
        before = path.read_bytes(), path.stat().st_mtime_ns
        self.stopped("INSTALL_RECORD_INVALID")
        self.assertEqual(before, (path.read_bytes(), path.stat().st_mtime_ns))
        self.probe.assert_not_called()

    def test_foreign_content_and_missing_binary(self):
        self.prefix.mkdir()
        foreign = self.prefix / "data"
        foreign.write_text("preserve")
        self.stopped("INSTALLATION_INCOMPLETE")
        self.record(ruby_version="3.4.11")
        self.stopped("INSTALLATION_INCOMPLETE")
        self.assertEqual(foreign.read_text(), "preserve")
        self.probe.assert_not_called()

    def test_record_syntax_precedes_absent_binary(self):
        path = self.record()
        for data in (b"x", b"\xff", b"{" + b" " * state.RECORD_LIMIT,
                     path.read_bytes().replace(b'"state":', b'"state": "complete", "state":')):
            path.write_bytes(data)
            self.stopped("INSTALL_RECORD_INVALID")

    def test_record_rejects_unknown_fields_or_coercions(self):
        for overrides in (dict(schema_version=True), dict(shared=1), dict(jit={"yjit": False}),
                          dict(state="pending"), dict(documentation="true"), dict(extra=42),
                          dict(source_sha256="x"), dict(canonical_prefix="/a/../b")):
            with self.subTest(overrides=overrides):
                self.record(**overrides)
                self.stopped("INSTALL_RECORD_INVALID")

    def test_record_symlink_fifo_or_writable(self):
        path = self.record()
        for mode in (0o666, 0o000):
            path.chmod(mode)
            self.stopped("INSTALL_RECORD_INVALID")
        path.unlink()
        path.symlink_to(self.root / "absent")
        self.stopped("INSTALL_RECORD_INVALID")
        path.unlink()
        os.mkfifo(path)
        self.stopped("INSTALL_RECORD_INVALID")

    def test_record_precedence_and_no_execution(self):
        binary = self.binary()
        self.record(ruby_version="3.4.11", shared=False)
        self.stopped("VERSION_MISMATCH")
        self.record(shared=False)
        self.stopped("BUILD_CONTRACT_MISMATCH")
        binary.chmod(0o644)
        self.stopped("INSTALLATION_INCOMPLETE")
        binary.chmod(0o777)
        self.stopped("UNSAFE_PATH")
        self.probe.assert_not_called()

    def test_matching_record_skips_missing_workspace_but_requires_health(self):
        self.binary()
        self.record()
        self.req["workspace"] = str(self.root / "absent")
        self.assertEqual(self.inspect(), "installed_healthy")
        self.probe.assert_called_once()
        self.fs.assert_not_called()
        self.probe.side_effect = state.Stop("HEALTH_CHECK_FAILED: fixture")
        self.stopped("HEALTH_CHECK_FAILED")

    def test_residual_unselected_public_link_and_unrelated_ruby(self):
        ruby = self.binary()
        self.record()
        (self.public / "ruby").symlink_to(self.work)
        self.assertEqual(self.inspect(), "installed_healthy")
        (self.public / "rake").symlink_to(ruby)
        self.stopped("RESIDUAL_LINK")
        (self.public / "rake").unlink()
        (self.public / "rake").symlink_to("missing")
        self.stopped("LINK_STATE_UNCERTAIN")

    def test_dangling_link_into_absent_prefix_is_residual(self):
        (self.public / "ruby").symlink_to(self.prefix / "bin" / "ruby")
        self.stopped("RESIDUAL_LINK")
        self.assertFalse(self.prefix.exists())

    def test_identity_change_during_health(self):
        binary = self.binary()
        self.record()
        self.probe.side_effect = lambda *unused: binary.write_text("changed by another actor")
        self.stopped("UNSAFE_PATH")

    def test_missing_runtime_tree_stops_before_launching_ruby(self):
        self.binary()
        self.record()
        with patch.object(health, "bounded_output") as run:
            with self.assertRaisesRegex(state.Stop, "^HEALTH_CHECK_FAILED:"):
                state.inspect(self.req, health.health_check, str(self.public))
            run.assert_not_called()

    def test_runtime_tree_rejects_writable_code_and_excludes_the_gem_store(self):
        self.binary()
        ruby_dir = self.prefix / "lib" / "ruby"
        gems = ruby_dir / "gems"
        gems.mkdir(parents=True)
        (self.prefix / "lib" / "libruby.so").touch()
        (gems / "user-gem").write_text("package")
        (gems / "user-gem").chmod(0o666)
        code = ruby_dir / "rbconfig.rb"
        code.touch()
        health.check_runtime_tree(state.Observation(), self.prefix)
        code.chmod(0o666)
        with self.assertRaisesRegex(state.Stop, "^UNSAFE_PATH:"):
            health.check_runtime_tree(state.Observation(), self.prefix)
        code.unlink()
        code.symlink_to(gems / "user-gem")
        with self.assertRaisesRegex(state.Stop, "^UNSAFE_PATH:"):
            health.check_runtime_tree(state.Observation(), self.prefix)


class Health(unittest.TestCase):
    def probe(self, version="3.4.12", docs=True, response=None, feature=("features",)):
        prefix = Path("/opt/ruby")
        record = state.installation_record(version, prefix, "a" * 64, True, state.jit_settings(version), docs)
        args = ["--enable-shared", "--enable-rpath", "--enable-option-checking=fatal", "--disable-install-capi"]
        args.extend("--disable-" + key for key in record["jit"])
        args.extend(["--enable-install-doc", "--enable-install-rdoc"] if docs else ["--disable-install-doc"])
        identity = ["identity", "/opt/ruby/bin/ruby", "/opt/ruby", "yes", " ".join(args), "false", "no", "no",
                    "/opt/ruby/lib/libruby.so.3.4"]
        output = identity if response is None else response(identity)
        with patch.object(health, "check_runtime_tree", return_value={"/opt/ruby/lib/libruby.so.3.4"}), patch.object(
                health, "bounded_output", side_effect=[output, list(feature)]) as run:
            try:
                health.health_check(Mock(), prefix, record)
            finally:
                self.calls = run.call_count

    def test_identity_and_libraries_for_both_series_with_docs_on_and_off(self):
        for version in ("3.4.12", "4.0.9"):
            for docs in (True, False):
                with self.subTest(version=version, docs=docs):
                    self.probe(version, docs)
                    self.assertEqual(self.calls, 2)

    def test_runtime_mismatch_precedes_extension_check(self):
        for response, reason in ((lambda row: ["version", "3.3.6"], "VERSION_MISMATCH"),
                                 (lambda row: ["version", "corrupt"], "HEALTH_CHECK_FAILED"),
                                 (lambda row: ["load_path"], "BUILD_CONTRACT_MISMATCH"),
                                 (lambda row: ["incomplete"], "HEALTH_CHECK_FAILED"),
                                 (lambda row: row[:-1], "BUILD_CONTRACT_MISMATCH"),
                                 (lambda row: row[:-1] + ["/usr/lib64/libruby.so"], "BUILD_CONTRACT_MISMATCH"),
                                 (lambda row: row[:4] + ["--enable-shared"] + row[5:], "BUILD_CONTRACT_MISMATCH"),
                                 (lambda row: row[:6] + ["yes"] + row[7:], "BUILD_CONTRACT_MISMATCH")):
            with self.subTest(reason=reason), self.assertRaisesRegex(state.Stop, "^" + reason + ":"):
                self.probe(response=response)
            self.assertEqual(self.calls, 1)

    def test_missing_required_feature_stops_the_rerun(self):
        with self.assertRaisesRegex(state.Stop, "^HEALTH_CHECK_FAILED:"):
            self.probe(feature=["incomplete"])
        self.assertEqual(self.calls, 2)

    @unittest.skipUnless(sys.platform.startswith("linux"), "target process groups require Linux")
    def test_output_limit_timeout_status_and_environment(self):
        start = [sys.executable, "-I", "-c"]
        self.assertEqual(health.bounded_output(start + ["print('ok',end='')"]), ["ok"])
        for script, bounds in (("print('x'*10000)", {"limit": 32}),
                               ("import time;time.sleep(3)", {"timeout": 0.1}),
                               ("raise SystemExit(2)", {})):
            with self.assertRaisesRegex(state.Stop, "^HEALTH_CHECK_FAILED:"):
                health.bounded_output(start + [script], **bounds)
        with patch.dict(os.environ, {"RUBYOPT": "bad", "LD_LIBRARY_PATH": "bad"}):
            self.assertEqual(health.bounded_output(start + [
                "import os;print(os.getcwd(),os.environ.get('RUBYOPT'),os.environ.get('LD_LIBRARY_PATH'),end='')"
            ]), ["/ None None"])

    def test_build_flags_and_ambiguous_overrides(self):
        self.assertTrue(health.configurable_flags(["--enable-shared", "--disable-yjit"], {"shared": "yes", "yjit": "no"}))
        self.assertFalse(health.configurable_flags(["--disable-yjit", "--enable-yjit=yes"], {"yjit": "no"}))
        self.assertFalse(health.configurable_flags([], {"install-capi": "no"}))


if __name__ == "__main__":
    unittest.main()

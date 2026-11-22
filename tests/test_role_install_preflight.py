"""Regression checks for verified extraction and publication of new installation records."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "module_utils"))
from ruby_install_preflight import archive, build, state


class InstallTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        self.prefix = self.work / "managed"
        self.version = "3.4.12"
        self.root = "ruby-" + self.version
        self.record = state.installation_record(self.version, self.prefix, "a" * 64, True,
                                                state.jit_settings(self.version), True)

    def source(self, extra=(), trailing=b""):
        stream = io.BytesIO()
        base = [(self.root + "/" + name, tarfile.REGTYPE, "") for name in ("configure", "configure.ac", "version.h")]
        with tarfile.open(fileobj=stream, mode="w") as tar:
            for name, kind, target in base + list(extra):
                member = tarfile.TarInfo(name)
                member.type, member.linkname = kind, target
                member.mode = 0o755 if name.endswith("/configure") else 0o644
                member.size = 1 if kind == tarfile.REGTYPE else 0
                tar.addfile(member, io.BytesIO(b"x"))
        data = gzip.compress(stream.getvalue() + trailing)
        (self.work / "source.tar.gz").write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def extract(self, digest):
        # Non-root developer runs use a private file owned by the test process.
        with patch.object(archive, "trusted_file", side_effect=lambda info: stat.S_ISREG(info.st_mode)
                          and info.st_uid == os.geteuid() and not info.st_mode & 0o022):
            return archive.extract(self.work, self.version, digest)

    def test_valid_sources_and_internal_links(self):
        digest = self.source([(self.root + "/alias", tarfile.SYMTYPE, "configure"),
                              (self.root + "/hard", tarfile.LNKTYPE, self.root + "/version.h")])
        root = self.extract(digest)
        self.assertEqual((root / "alias").resolve(), root / "configure")
        self.assertTrue(os.access(root / "configure", os.X_OK))
        self.assertTrue((root / "hard").samefile(root / "version.h"))

    def test_bad_digest_never_creates_extraction_directory(self):
        self.source()
        with self.assertRaisesRegex(state.Stop, "SOURCE_CHECKSUM_MISMATCH"):
            self.extract("0" * 64)
        self.assertFalse((self.work / "source").exists())

    def test_archive_structure_checked_before_first_write(self):
        cases = [[("other/version.h", tarfile.REGTYPE, "")],
                 [(self.root + "/configure", tarfile.REGTYPE, "")],
                 [(self.root + "/link", tarfile.SYMTYPE, "../outside")],
                 [(self.root + "/link", tarfile.SYMTYPE, "version.h"), (self.root + "/link/child", tarfile.REGTYPE, "")]]
        for extra in cases:
            with self.subTest(extra=extra), self.assertRaisesRegex(state.Stop, "SOURCE_ARCHIVE_INVALID"):
                self.extract(self.source(extra))
            self.assertFalse((self.work / "source").exists())

    def test_trailing_data_is_rejected(self):
        with self.assertRaisesRegex(state.Stop, "SOURCE_ARCHIVE_INVALID"):
            self.extract(self.source(trailing=b"x" * 512))
        self.assertFalse((self.work / "source").exists())

    def test_completed_record_cannot_replace_an_existing_record(self):
        self.prefix.mkdir()
        with (self.prefix / build.MARKER).open("xb") as stream:
            fd = os.open(self.prefix, os.O_RDONLY | os.O_DIRECTORY)
            try:
                (self.prefix / state.RECORD).write_bytes(b"existing")
                with self.assertRaises(FileExistsError):
                    build.publish(self.prefix, fd, stream, self.record)
            finally:
                os.close(fd)
        self.assertEqual((self.prefix / state.RECORD).read_bytes(), b"existing")

    def install_until_verify(self, success):
        request = dict(version=self.version, prefix=str(self.prefix), digest="a" * 64,
                       documentation=True, jobs=1, keep=True)
        # Exercise real marker, locking and hard-link publication in an unprivileged temporary prefix.
        def verify(prefix, record, env, link_commands):
            self.assertFalse((prefix / state.RECORD).exists())
            self.assertTrue((prefix / build.MARKER).is_file())
            self.assertEqual(record, self.record)
            if not success:
                raise state.Stop("failed verification")
        mode = os.umask(0o022)
        self.addCleanup(os.umask, mode)
        with patch.object(build, "check_work", return_value=self.work), \
                patch.object(build, "vacant_prefix", return_value=self.prefix), \
                patch.object(build, "extract", return_value=self.work), \
                patch.object(build, "run_logged"), patch.object(build, "verify_installation", side_effect=verify), \
                patch.object(state, "trusted_dir"), patch.object(build, "trusted_dir"):
            build.install(request, {})

    def test_postinstall_failure_preserves_workspace_and_unfinished_prefix(self):
        with self.assertRaisesRegex(state.Stop, "failed verification"):
            self.install_until_verify(False)
        self.assertFalse((self.prefix / state.RECORD).exists())
        self.assertTrue((self.prefix / build.MARKER).is_file())
        self.assertTrue((self.work / "build").is_dir())

    def test_successful_verification_publishes_schema_once(self):
        sibling = self.work / "previous-run.log"
        sibling.write_bytes(b"keep this log")
        self.install_until_verify(True)
        self.assertEqual(json.loads((self.prefix / state.RECORD).read_bytes()), self.record)
        self.assertFalse((self.prefix / build.MARKER).exists())
        self.assertTrue((self.work / "build").is_dir())
        self.assertEqual(sibling.read_bytes(), b"keep this log")

    def test_work_cleanup_requires_the_same_private_directory(self):
        work = self.work / "ruby-install-aa"
        work.mkdir(mode=0o700)
        info = work.stat()
        resolver = build.Observation()
        def root_info(path, **_kwargs):
            path = Path(path)
            result = path.stat()
            fields = list(result)
            fields[4] = 0
            return path, os.stat_result(fields), path
        request = dict(workspace=str(self.work), work=str(work), work_dev=info.st_dev, work_inode=info.st_ino)
        with patch.object(resolver, "resolve", side_effect=root_info), patch.object(build, "Observation", return_value=resolver):
            self.assertEqual(build.check_work(request), work)
            request["work_inode"] += 1
            with self.assertRaisesRegex(state.Stop, "WORKSPACE_INVALID"):
                build.check_work(request)
            request["work_inode"] = info.st_ino
            work.chmod(0o755)
            with self.assertRaisesRegex(state.Stop, "WORKSPACE_INVALID"):
                build.check_work(request)


if __name__ == "__main__":
    unittest.main()

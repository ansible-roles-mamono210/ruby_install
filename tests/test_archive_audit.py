"""Malicious archive fixtures, entirely offline; no extraction or execution."""
import contextlib
import gzip
import io
import os
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from test_source_probe import Response, archive_report, h, report, w

ROOT = 'ruby-3.4.12'


def entry(name, data=b'x', kind=tarfile.REGTYPE, target='', mode=0o644, pax=None):
    item = tarfile.TarInfo(name)
    item.type, item.linkname, item.mode = kind, target, mode
    item.size = len(data) if kind == tarfile.REGTYPE else 0
    item.pax_headers = pax or {}
    return item, data if kind == tarfile.REGTYPE else b''


def valid_entries():
    return [entry(ROOT, kind=tarfile.DIRTYPE),
            *(entry(ROOT + '/' + name) for name in w.REQUIRED_FILES)]


def tar_bytes(entries, format=tarfile.USTAR_FORMAT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=format) as archive:
        for item, data in entries:
            archive.addfile(item, io.BytesIO(data))
    return output.getvalue()


class ArchiveTests(unittest.TestCase):
    def audit(self, entries=None, raw=None, compressed=None, format=tarfile.USTAR_FORMAT):
        if compressed is None:
            compressed = gzip.compress(tar_bytes(valid_entries() if entries is None else entries, format)
                                       if raw is None else raw)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source.tar.gz'
            source.write_bytes(compressed)
            with patch.object(tarfile.TarFile, 'extract', side_effect=AssertionError('extract')), \
                    patch.object(tarfile.TarFile, 'extractall', side_effect=AssertionError('extractall')):
                result = w.audit_archive(source, '3.4.12', time.monotonic() + 30)
            self.assertEqual(list(Path(directory).iterdir()), [source])
            return result

    def rejected(self, extra, reason, **kwargs):
        with self.assertRaisesRegex(w.Stop, reason):
            self.audit(valid_entries() + extra, **kwargs)

    def test_plain_archive_has_counts_and_no_extraction(self):
        value = self.audit()
        self.assertEqual(value['members'], 4)
        self.assertEqual(value['regular_file_bytes'], 3)
        self.assertTrue(value['gzip_eof_verified'])
        self.assertFalse(value['members_extracted'])
        h.validate_archive(value, '3.4.12', w)

    def test_safe_symlink_relative_parent_and_hardlink(self):
        value = self.audit(valid_entries() + [entry(ROOT + '/sub/alias', kind=tarfile.SYMTYPE,
                                                   target='../configure'),
            entry(ROOT + '/hard', kind=tarfile.LNKTYPE, target=ROOT + '/configure')])
        self.assertEqual((value['types']['symlink'], value['types']['hardlink']), (1, 1))

    def test_internal_symlink_chain_and_directory_link(self):
        self.audit(valid_entries() + [entry(ROOT + '/d', kind=tarfile.DIRTYPE),
            entry(ROOT + '/a', kind=tarfile.SYMTYPE, target='d'),
            entry(ROOT + '/b', kind=tarfile.SYMTYPE, target='a/../configure')])

    def test_member_path_boundaries(self):
        for name in ('/tmp/escape', '../escape', ROOT + '/../escape', ROOT + '/a/../../escape',
                     'wrong-root/file', ROOT + '//file', ROOT + '/./file', ROOT + '/back\\slash',
                     ROOT + '/new\nline'):
            with self.subTest(name=name):
                self.rejected([entry(name)], 'ARCHIVE_PATH_INVALID')

    def test_duplicate_file_and_directory(self):
        for extra in (entry(ROOT + '/configure'), entry(ROOT, kind=tarfile.DIRTYPE)):
            self.rejected([extra], 'ARCHIVE_DUPLICATE')

    def test_file_or_link_parent_conflict_in_either_order(self):
        for kind in (tarfile.REGTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE):
            items = [entry(ROOT + '/a', kind=kind, target='configure'), entry(ROOT + '/a/child')]
            for pair in (items, items[::-1]):
                self.rejected(pair, 'ARCHIVE_PARENT_CONFLICT|ARCHIVE_HARDLINK_TARGET')

    def test_symlink_escape_absolute_and_control_targets(self):
        for target in ('/tmp/escape', '../escape', '../../escape', 'sub/../../../escape',
                       'bad\\target', 'bad\ntarget', ''):
            with self.subTest(target=target):
                self.rejected([entry(ROOT + '/link', kind=tarfile.SYMTYPE, target=target)],
                              'ARCHIVE_LINK_ESCAPE|ARCHIVE_LINK_TARGET')

    def test_link_resolution_does_not_collapse_parent_before_symlink(self):
        self.rejected([entry(ROOT + '/d', kind=tarfile.DIRTYPE),
            entry(ROOT + '/d/a', kind=tarfile.SYMTYPE, target='..'),
            entry(ROOT + '/x', kind=tarfile.SYMTYPE, target='d/a/../configure')], 'ARCHIVE_LINK_ESCAPE')

    def test_link_cycles_and_dangling_targets(self):
        self.rejected([entry(ROOT + '/a', kind=tarfile.SYMTYPE, target='b'),
                       entry(ROOT + '/b', kind=tarfile.SYMTYPE, target='a')], 'ARCHIVE_LINK_CYCLE')
        self.rejected([entry(ROOT + '/a', kind=tarfile.SYMTYPE, target='missing')], 'ARCHIVE_LINK_TARGET')

    def test_hardlinks_must_reference_direct_regular_file(self):
        for target in ('/tmp/out', '../out', ROOT + '/missing', ROOT):
            self.rejected([entry(ROOT + '/hard', kind=tarfile.LNKTYPE, target=target)],
                          'ARCHIVE_PATH_INVALID|ARCHIVE_HARDLINK_TARGET')

    def test_special_and_sparse_types_rejected(self):
        for kind in (tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE, tarfile.GNUTYPE_SPARSE, b'V'):
            self.rejected([entry(ROOT + '/special', kind=kind)], 'ARCHIVE_TYPE_OR_MODE',
                          format=tarfile.GNU_FORMAT)

    def test_privilege_bits_rejected(self):
        for mode in (0o4755, 0o2755, 0o6755):
            self.rejected([entry(ROOT + '/privileged', mode=mode)], 'ARCHIVE_TYPE_OR_MODE')

    def test_required_files_must_exist_nonempty_regular(self):
        for entries in (valid_entries()[:-1], [entry(ROOT, kind=tarfile.DIRTYPE)],
                        []):
            with self.assertRaisesRegex(w.Stop, 'ARCHIVE_REQUIRED_FILE'):
                self.audit(entries)
        items = valid_entries()
        items[-1] = entry(ROOT + '/version.h', data=b'')
        with self.assertRaisesRegex(w.Stop, 'ARCHIVE_REQUIRED_FILE'):
            self.audit(items)

    def test_root_cannot_be_file(self):
        with self.assertRaisesRegex(w.Stop, 'ARCHIVE_ROOT_INVALID'):
            self.audit([entry(ROOT)])

    def test_gnu_longname_and_longlink(self):
        name = ROOT + '/' + 'a' * 130
        self.audit(valid_entries() + [entry(name),
            entry(ROOT + '/alias', kind=tarfile.SYMTYPE, target='a' * 130)], format=tarfile.GNU_FORMAT)

    def test_pax_path_and_timestamp(self):
        self.audit(valid_entries() + [entry(ROOT + '/short', pax={'path': ROOT + '/' + 'a' * 130,
                                                                'mtime': '1.25'})],
                   format=tarfile.PAX_FORMAT)

    def test_pax_path_and_linkpath_cannot_override_safety(self):
        self.rejected([entry(ROOT + '/short', pax={'path': '/tmp/escape'})],
                      'ARCHIVE_PATH_INVALID', format=tarfile.PAX_FORMAT)
        self.rejected([entry(ROOT + '/link', kind=tarfile.SYMTYPE, target='configure',
                             pax={'linkpath': '../../escape'})], 'ARCHIVE_LINK_ESCAPE',
                      format=tarfile.PAX_FORMAT)

    def test_unknown_or_sparse_pax_extensions_fail_closed(self):
        for key in ('GNU.sparse.map', 'GNU.sparse.major', 'SCHILY.xattr.user.test'):
            self.rejected([entry(ROOT + '/pax', pax={key: '1'})],
                          'ARCHIVE_METADATA_UNSUPPORTED', format=tarfile.PAX_FORMAT)

    def test_corrupt_or_truncated_gzip(self):
        data = bytearray(gzip.compress(tar_bytes(valid_entries())))
        data[-8] ^= 1
        for compressed in (bytes(data), bytes(data[:-8]), b'not gzip'):
            with self.assertRaisesRegex(w.Stop, 'ARCHIVE_FORMAT_INVALID'):
                self.audit(compressed=compressed)

    def test_tar_header_checksum_corrupt(self):
        raw = bytearray(tar_bytes(valid_entries())); raw[10] ^= 1
        with self.assertRaisesRegex(w.Stop, 'ARCHIVE_FORMAT_INVALID'):
            self.audit(raw=raw)

    def test_truncated_tar_body_and_missing_end_blocks(self):
        for size in (600, 512 * 7, 512 * 8):
            with self.assertRaisesRegex(w.Stop, 'ARCHIVE_TRUNCATED'):
                self.audit(raw=tar_bytes(valid_entries())[:size])

    def test_hidden_data_after_end_and_concatenated_gzip(self):
        raw = tar_bytes(valid_entries())
        for compressed in (gzip.compress(raw + b'evil'), gzip.compress(raw) + gzip.compress(raw)):
            with self.assertRaisesRegex(w.Stop, 'ARCHIVE_TRAILING_DATA'):
                self.audit(compressed=compressed)

    def test_nonzero_payload_padding_rejected(self):
        raw = bytearray(tar_bytes(valid_entries())); raw[1025] = 1
        with self.assertRaisesRegex(w.Stop, 'ARCHIVE_PADDING_INVALID'):
            self.audit(raw=raw)

    def test_expansion_member_file_metadata_and_deadline_bounds(self):
        for name, value, reason in (('MAX_TAR_BYTES', 1024, 'EXPANSION_LIMIT'),
                                    ('MAX_HEADERS', 2, 'HEADER_LIMIT'),
                                    ('MAX_FILE_BYTES', 0, 'SIZE_INVALID'),
                                    ('MAX_PATH', 8, 'PATH_INVALID')):
            with patch.object(w, name, value), self.assertRaisesRegex(w.Stop, reason):
                self.audit()
        with patch.object(w, 'MAX_METADATA', 2), self.assertRaisesRegex(w.Stop, 'METADATA_LIMIT'):
            self.audit(valid_entries() + [entry(ROOT + '/long', pax={'mtime': '1.25'})],
                       format=tarfile.PAX_FORMAT)
        with patch.object(w.time, 'monotonic', side_effect=[0, 31]), \
                self.assertRaisesRegex(w.Stop, 'TIME_LIMIT'):
            self.audit()

    def test_pax_invalid_frames_and_duplicate_keys(self):
        for data in (b'0 path=x\n', b'99 path=x\n', b'10 path=x!', b'8 path=x\n',
                     b'9 path=x\n9 path=y\n'):
            with self.assertRaises(w.Stop):
                w.pax_records(data)

    def test_global_pax_metadata(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT,
                          pax_headers={'mtime': '1.25'}) as archive:
            for item, data in valid_entries():
                archive.addfile(item, io.BytesIO(data))
        self.audit(raw=output.getvalue())

    def test_global_path_override_is_not_supported(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT,
                          pax_headers={'path': ROOT + '/override'}) as archive:
            for item, data in valid_entries():
                archive.addfile(item, io.BytesIO(data))
        with self.assertRaisesRegex(w.Stop, 'ARCHIVE_METADATA_UNSUPPORTED'):
            self.audit(raw=output.getvalue())

    def test_pax_size_checked_before_payload_read(self):
        self.rejected([entry(ROOT + '/huge', pax={'size': str(w.MAX_FILE_BYTES + 1)})],
                      'ARCHIVE_SIZE_INVALID', format=tarfile.PAX_FORMAT)

    def test_link_chain_has_finite_bound(self):
        links = [entry(ROOT + '/a' + str(i), kind=tarfile.SYMTYPE,
                       target='a' + str(i + 1) if i < 41 else 'configure') for i in range(42)]
        self.rejected(links, 'ARCHIVE_LINK_CYCLE_OR_DEPTH')

    def test_unterminated_extension_is_not_accepted(self):
        item = tarfile.TarInfo('././@LongLink')
        item.type, item.size = tarfile.GNUTYPE_LONGNAME, 2
        raw = item.tobuf(format=tarfile.GNU_FORMAT) + b'x\0' + bytes(510) + bytes(1024)
        with self.assertRaisesRegex(w.Stop, 'ARCHIVE_END_INVALID'):
            self.audit(raw=raw)

    def test_extension_chain_limit(self):
        item = tarfile.TarInfo('././@PaxHeader')
        item.type, item.size = tarfile.XGLTYPE, 11
        # A valid repeated global timestamp remains bounded even before a member.
        record = b'11 mtime=1\n'
        raw = (item.tobuf(format=tarfile.USTAR_FORMAT) + record + bytes(512 - len(record))) * 9
        with self.assertRaisesRegex(w.Stop, 'ARCHIVE_METADATA_LIMIT'):
            self.audit(raw=raw)


class AuditIntegrationTests(unittest.TestCase):
    def test_existing_download_flags_do_not_authorize_archive_audit(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'CIRCLECI': 'true', 'CIRCLE_BRANCH': h.BRANCH}, clear=True), \
                patch.object(h.platform, 'system', return_value='Linux'), \
                patch.object(h.platform, 'machine', return_value='x86_64'), \
                patch.object(h, 'load') as load, contextlib.redirect_stdout(io.StringIO()):
            output = Path(directory) / 'result.json'
            result = h.main(['--output', str(output), '--allow-pull', '--ephemeral-ci',
                             '--allow-source-download'])
            self.assertEqual(result, 3)
            self.assertFalse(output.exists())
            load.assert_not_called()

    def test_checksum_failure_prevents_archive_parser(self):
        conn = Mock(); conn.getresponse.return_value = Response()
        with patch.object(w.http.client, 'HTTPSConnection', return_value=conn), \
                patch.object(w, 'receive', side_effect=w.Stop('SHA256_MISMATCH')), \
                patch.object(w, 'audit_archive') as audit, self.assertRaisesRegex(w.Stop, 'SHA256'):
            w.download(w.SOURCES[0], {})
        audit.assert_not_called()

    def test_audit_failure_cleans_source_and_does_not_retry(self):
        paths = []
        conn = Mock(); conn.getresponse.return_value = Response()

        def receive(response, path, checksum, deadline):
            path.write_bytes(b'archive'); paths.append(path)
            return {'checksum_match': True}

        with patch.object(w.http.client, 'HTTPSConnection', return_value=conn), \
                patch.object(w, 'receive', side_effect=receive), \
                patch.object(w, 'audit_archive', side_effect=w.Stop('ARCHIVE_DUPLICATE')) as audit, \
                self.assertRaisesRegex(w.Stop, 'ARCHIVE_DUPLICATE'):
            w.download(w.SOURCES[0], {})
        audit.assert_called_once()
        self.assertEqual(conn.request.call_count, 1)
        self.assertTrue(paths and all(not p.exists() for p in paths))

    def test_host_rejects_false_or_inconsistent_audit_claims(self):
        for field, value in (('members_extracted', True), ('gzip_eof_verified', False),
                             ('headers', True), ('members', 5), ('tar_stream_bytes', 999),
                             ('regular_file_bytes', w.MAX_TAR_BYTES + 1),
                             ('required_regular_files', []), ('root', 'ruby-wrong')):
            data = report(); data['results'][0]['archive'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(h.Stop, 'ARCHIVE_RESULT'):
                h.validate(data, w)

    def test_archive_failure_summary_is_bounded(self):
        value = h.failure_summary({'reason': 'ARCHIVE_DUPLICATE', 'member': 'SECRET'})
        self.assertEqual(value['reason'], 'ARCHIVE_DUPLICATE')
        self.assertNotIn('SECRET', str(value))


if __name__ == '__main__':
    unittest.main()

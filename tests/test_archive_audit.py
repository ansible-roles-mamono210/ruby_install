"""Malicious archive fixtures, entirely offline; no extraction or execution."""
import contextlib
import copy
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
        value = h.failure_summary({'reason': 'ARCHIVE_DUPLICATE', 'member': 'SECRET'}, w)
        self.assertEqual(value['reason'], 'ARCHIVE_DUPLICATE')
        self.assertNotIn('SECRET', str(value))


class TruncationDiagnosticTests(unittest.TestCase):
    audit = ArchiveTests.audit
    def diagnostic(self, raw):
        with self.assertRaises(w.ArchiveTruncated) as captured:
            self.audit(raw=raw)
        self.assertEqual(str(captured.exception), 'ARCHIVE_TRUNCATED')
        result = captured.exception.diagnostic
        self.assertEqual(h.truncation_diagnostic(result, w), result)
        return result

    def test_header_position_is_distinct_from_payload(self):
        d = self.diagnostic(tar_bytes(valid_entries())[:600])
        self.assertEqual((d['stage'], d['header_offset'], d['stream_offset'],
                          d['expected_bytes'], d['received_bytes'], d['headers_seen']),
                         ('header', 512, 512, 512, 88, 1))

    def test_missing_first_and_second_end_blocks_are_distinct(self):
        raw = tar_bytes(valid_entries())
        first = self.diagnostic(raw[:3584])
        second = self.diagnostic(raw[:4096])
        self.assertEqual((first['stage'], first['stream_offset']), ('header', 3584))
        self.assertEqual((second['stage'], second['stream_offset']), ('second_end_block', 4096))
        self.assertEqual(first['received_bytes'], 0)
        self.assertEqual(second['received_bytes'], 0)

    def test_payload_records_remaining_bytes_and_no_member_name(self):
        raw = tar_bytes([entry(ROOT, kind=tarfile.DIRTYPE),
                         entry(ROOT + '/SECRET', b'0123456789')])
        d = self.diagnostic(raw[:1027])
        self.assertEqual((d['stage'], d['headers_seen'], d['header_offset'],
                          d['stream_offset'], d['declared_size'], d['payload_remaining'],
                          d['expected_bytes'], d['received_bytes']),
                         ('file_payload', 2, 512, 1024, 10, 10, 10, 3))
        self.assertNotIn('SECRET', str(d))

    def test_payload_position_after_one_full_read_chunk(self):
        raw = tar_bytes([entry(ROOT, kind=tarfile.DIRTYPE),
                         entry(ROOT + '/large', b'x' * (w.BLOCK + 10))])
        d = self.diagnostic(raw[:1024 + w.BLOCK + 2])
        self.assertEqual((d['stream_offset'], d['declared_size'], d['payload_remaining'],
                          d['expected_bytes'], d['received_bytes']),
                         (1024 + w.BLOCK, w.BLOCK + 10, 10, 10, 2))

    def test_padding_position_is_distinct_from_payload(self):
        d = self.diagnostic(tar_bytes(valid_entries())[:1125])
        self.assertEqual((d['stage'], d['stream_offset'], d['expected_bytes'],
                          d['received_bytes'], d['payload_remaining']),
                         ('file_padding', 1025, 511, 100, 0))

    def test_extension_payload_and_padding_are_distinct(self):
        item = tarfile.TarInfo('././@LongLink')
        item.type, item.size = tarfile.GNUTYPE_LONGNAME, 10
        header = item.tobuf(format=tarfile.GNU_FORMAT)
        body = self.diagnostic(header + b'abc')
        padding = self.diagnostic(header + b'123456789\0' + bytes(100))
        self.assertEqual((body['stage'], body['expected_bytes'], body['received_bytes']),
                         ('extension_payload', 10, 3))
        self.assertEqual((padding['stage'], padding['expected_bytes'], padding['received_bytes']),
                         ('extension_padding', 502, 100))

    def test_gzip_corruption_is_not_relabelled_as_tar_truncation(self):
        compressed = bytearray(gzip.compress(tar_bytes(valid_entries())))
        compressed[-8] ^= 1
        with self.assertRaisesRegex(w.Stop, 'ARCHIVE_FORMAT_INVALID') as captured:
            self.audit(compressed=bytes(compressed))
        self.assertNotIsInstance(captured.exception, w.ArchiveTruncated)

    def test_host_rejects_invalid_diagnostic_without_leaking_fields(self):
        good = self.diagnostic(tar_bytes(valid_entries())[:600])
        bad_values = []
        for key, value in (('member_name', 'SECRET'), ('stage', 'SECRET'),
                           ('member_kind', 'SECRET'), ('expected_bytes', True),
                           ('stream_offset', -1), ('stream_offset', w.MAX_TAR_BYTES + 1),
                           ('headers_seen', w.MAX_HEADERS + 1), ('received_bytes', 512),
                           ('header_offset', 1), ('payload_remaining', 1),
                           ('declared_size', w.MAX_FILE_BYTES + 1), ('stage', [])):
            bad_values.append(dict(good, **{key: value}))
        missing = dict(good); del missing['header_offset']; bad_values.append(missing)
        bad_values.extend((None, [], 'SECRET'))
        for diagnostic in bad_values:
            with self.subTest(diagnostic=diagnostic):
                result = h.failure_summary({'reason': 'ARCHIVE_TRUNCATED',
                    'results': [{'version': '3.4.12', 'archive_failure': diagnostic}]}, w)
                self.assertEqual(result['observations'][0],
                                 {'version': '3.4.12', 'archive_failure_diagnostic_rejected': True})
                self.assertNotIn('SECRET', str(result))

    def test_checksum_evidence_requires_fixed_known_digest_and_valid_size(self):
        row = report()['results'][0]
        output = h.failure_summary({'reason': 'ARCHIVE_TRUNCATED', 'results': [row]}, w)
        self.assertEqual(output['observations'][0]['sha256'], w.SOURCES[0][2])
        self.assertEqual(output['observations'][0]['bytes'], 100)
        for key, value in (('sha256', 'SECRET'), ('checksum_match', False), ('bytes', True),
                           ('bytes', 0), ('bytes', w.MAX_BYTES + 1), ('version', 'unknown')):
            modified = copy.deepcopy(row); modified[key] = value
            result = h.failure_summary({'reason': 'ARCHIVE_TRUNCATED', 'results': [modified]}, w)
            self.assertNotIn('sha256', result['observations'][0])
            self.assertNotIn('bytes', result['observations'][0])

    def test_download_diagnostic_reaches_host_and_still_cleans_up(self):
        raw = tar_bytes(valid_entries())[:600]
        compressed = gzip.compress(raw)
        digest = w.hashlib.sha256(compressed).hexdigest()
        source = ('3.4.12', w.SOURCES[0][1], digest)
        conn = Mock(); conn.getresponse.return_value = Response(compressed)
        row = {'version': '3.4.12'}
        paths = []
        original = w.audit_archive

        def capture(path, version, deadline):
            paths.append(path)
            return original(path, version, deadline)

        with patch.object(w, 'SOURCES', (source,)), \
                patch.object(w.http.client, 'HTTPSConnection', return_value=conn), \
                patch.object(w, 'audit_archive', side_effect=capture), \
                self.assertRaises(w.ArchiveTruncated):
            w.download(source, row)
        self.assertEqual(conn.request.call_count, 1)
        conn.close.assert_called_once()
        self.assertTrue(paths and all(not p.exists() for p in paths))
        with patch.object(w, 'SOURCES', (source,)):
            result = h.failure_summary({'reason': 'ARCHIVE_TRUNCATED', 'results': [row]}, w)
        self.assertEqual(result['observations'][0]['archive_failure']['stream_offset'], 512)
        self.assertEqual(result['observations'][0]['sha256'], digest)
        self.assertEqual(result['observations'][0]['bytes'], len(compressed))


if __name__ == '__main__':
    unittest.main()

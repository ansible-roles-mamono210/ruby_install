"""r27: one guarded RPM transaction in a disposable CI container, never a Role."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

SCHEMA = 'ruby-p1-install-container-r27'
SUCCESS = 'DEPENDENCIES_INSTALLED_AND_SMOKE_CHECKED'
STAGES = ('identity', 'baseline', 'resolve', 'plan_check', 'download', 'signatures',
          'transaction', 'rpm_check', 'smoke', 'finished')
FIELDS = ('name', 'epoch', 'version', 'release', 'arch')
MAX_DOWNLOAD = 512 * 1024 * 1024
MAX_INSTALLED_SIZE = 2 * 1024 * 1024 * 1024
MIN_FREE = 5 * 1024 * 1024 * 1024
PLAN_SHA = 'dab9f189074751b8555cd8dd9edec219d6d8b1e0e275d3b569772f28fa332f27'
SMOKE_NAMES = ('fresh_python', 'compiler_link', 'compiled_program')
REASONS = frozenset({'IDENTITY', 'BASELINE_CHANGED', 'TRANSACTION_PLAN_CHANGED',
    'UNPAIRED_REMOVAL', 'NON_UPGRADE_REPLACEMENT', 'TRANSACTION_ACTION',
    'DOWNLOAD_LIMIT', 'RPM_CHECKSUM', 'RPM_SIGNATURE', 'KEY_SOURCE', 'KEY_IDENTITY',
    'RPM_DELTA', 'CONFIGURATION_CHANGED', 'SPACE_LOW', 'DNF_POLICY', 'TIME_LIMIT',
    'SMOKE_FAILED', 'TRANSACTION_CALLBACK_ERROR', 'API_OR_RUNTIME_ERROR'})


class Stop(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise Stop(reason)


def key(row):
    return tuple(row[k] for k in FIELDS)


def inventory(rpm):
    ts = rpm.TransactionSet()
    rows = []
    for header in ts.dbMatch():
        need(len(rows) < 4096, 'RPM_DELTA')
        row = {k: str(header[k]) for k in FIELDS}
        if row['epoch'] == 'None':
            row['epoch'] = '0'
        need(all(re.fullmatch(r'[A-Za-z0-9_+.~:^@-]{1,160}', v) for v in row.values()), 'RPM_DELTA')
        rows.append(row)
    return sorted(rows, key=key)


def check_plan(install, remove, expected, compare):
    # Exact NEVRA and origin, not just counts. A changed mirror snapshot stops this run.
    need(install == expected['install_set'] and remove == expected['remove_set'],
         'TRANSACTION_PLAN_CHANGED')
    for old in remove:
        paired = [p for p in install if (p['name'], p['arch']) == (old['name'], old['arch'])]
        need(len(paired) == 1, 'UNPAIRED_REMOVAL')
        new = paired[0]
        need(compare(tuple(new[k] for k in ('epoch', 'version', 'release')),
                     tuple(old[k] for k in ('epoch', 'version', 'release'))) > 0,
             'NON_UPGRADE_REPLACEMENT')


def check_delta(before, after, plan):
    # Keys may be imported separately; ordinary RPM changes must exactly match the solver.
    ordinary = lambda rows: {key(r) for r in rows if r['name'] != 'gpg-pubkey'}
    old, new = ordinary(before), ordinary(after)
    need(len(old) == len([r for r in before if r['name'] != 'gpg-pubkey']) and
         len(new) == len([r for r in after if r['name'] != 'gpg-pubkey']), 'RPM_DELTA')
    adds = {key(r) for r in plan['install_set']}
    removes = {key(r) for r in plan['remove_set']}
    need(removes <= old and new == (old - removes) | adds, 'RPM_DELTA')
    keys_before = {key(r) for r in before if r['name'] == 'gpg-pubkey'}
    keys_after = {key(r) for r in after if r['name'] == 'gpg-pubkey'}
    need(keys_before <= keys_after and len(keys_after - keys_before) <= 4, 'RPM_DELTA')
    return {'added_or_upgraded': len(adds), 'replaced_old_versions': len(removes),
            'new_package_names': len({r['name'] for r in after} - {r['name'] for r in before}
                                     - {'gpg-pubkey'}),
            'public_keys_added': len(keys_after - keys_before), 'exact_plan_match': True}


def trusted_keys(base):
    # Trust only public-key bytes packaged in the digest-fixed image, no remote key import.
    found = {}
    for repo in base.repos.iter_enabled():
        for uri in repo.gpgkey:
            parsed = urlsplit(uri)
            need(parsed.scheme == 'file' and not parsed.netloc and not parsed.query
                 and not parsed.fragment and '%' not in parsed.path, 'KEY_SOURCE')
            path = Path(parsed.path)
            root = Path('/etc/pki/rpm-gpg')
            need(path.is_absolute() and root in path.parents and root in path.resolve().parents,
                 'KEY_SOURCE')
            info = path.stat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
                 and 0 < info.st_size <= 65536, 'KEY_SOURCE')
            found[uri] = hashlib.sha256(path.read_bytes()).hexdigest()
    need(0 < len(found) <= 4, 'KEY_SOURCE')
    return found


def download_and_verify(base, packages, report, dependency):
    need(sum(int(p.downloadsize) for p in packages) <= MAX_DOWNLOAD, 'DOWNLOAD_LIMIT')
    need(sum(int(p.installsize) for p in packages) <= MAX_INSTALLED_SIZE, 'DOWNLOAD_LIMIT')
    approved_keys = trusted_keys(base)
    report['public_key_file_sha256'] = sorted(set(approved_keys.values()))
    base.conf.assumeyes = False
    base.conf.assumeno = False
    report['stage'] = 'download'
    base.download_packages(packages)
    report['rpm_downloaded'] = True
    report['stage'] = 'signatures'
    records = []
    for package in packages:
        path = Path(package.localPkg())
        need(not path.is_symlink() and path.is_file() and
             Path(base.conf.cachedir).resolve() in path.resolve().parents, 'RPM_CHECKSUM')
        need(package.verifyLocalPkg() is True, 'RPM_CHECKSUM')
        result, _ = base.package_signature_check(package)
        if result == 1:
            def approve(info):
                uri = info.get('keyurl')
                fingerprint = info.get('fingerprint')
                need(uri in approved_keys and
                     hashlib.sha256(Path(urlsplit(uri).path).read_bytes()).hexdigest()
                     == approved_keys[uri], 'KEY_SOURCE')
                need(type(fingerprint) is str and
                     re.fullmatch(r'[0-9A-Fa-f]{40,64}', fingerprint) is not None, 'KEY_IDENTITY')
                report['imported_key_fingerprints'].append(fingerprint.upper())
                return True
            base.package_import_key(package, fullaskcb=approve)
            result, _ = base.package_signature_check(package)
        need(type(result) is int and result == 0, 'RPM_SIGNATURE')
        records.append({'package': dependency.package(package),
                        'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                        'bytes': path.stat().st_size, 'signature_verified': True})
    need(sum(row['bytes'] for row in records) <= MAX_DOWNLOAD, 'DOWNLOAD_LIMIT')
    report['rpms'] = sorted(records, key=lambda r: key(r['package']))
    report['all_signatures_verified'] = True


SMOKE_C = '''#include <stdio.h>
#include <openssl/ssl.h>
#include <yaml.h>
#include <zlib.h>
#include <ffi.h>
int main(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    yaml_parser_t parser;
    ffi_cif cif;
    if (!ctx || !yaml_parser_initialize(&parser) || !zlibVersion() ||
        ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 0, &ffi_type_void, NULL) != FFI_OK) return 1;
    yaml_parser_delete(&parser); SSL_CTX_free(ctx);
    puts("BUILD_DEPENDENCIES_OK"); return 0;
}
'''


def smoke(directory, records=None):
    source, program = Path(directory) / 'probe.c', Path(directory) / 'probe'
    source.write_text(SMOKE_C)
    commands = [
        ('fresh_python', ['/usr/bin/python3', '-I', '-B', '-c',
         'import dnf,rpm,ssl; print("PYTHON_DNF_RPM_SSL_OK")'], 'PYTHON_DNF_RPM_SSL_OK\n'),
        ('compiler_link', ['/usr/bin/gcc', str(source), '-o', str(program),
         '-lssl', '-lcrypto', '-lyaml', '-lz', '-lffi'], ''),
        ('compiled_program', [str(program)], 'BUILD_DEPENDENCIES_OK\n')]
    if records is None:
        records = []
    for name, argv, expected in commands:
        started = time.monotonic()
        p = subprocess.run(argv, capture_output=True, text=True, timeout=90, check=False,
                           env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': directory})
        records.append({'name': name, 'returncode': p.returncode, 'stderr_bytes': len(p.stderr.encode()),
                        'output_match': p.stdout == expected,
                        'elapsed_seconds': round(time.monotonic() - started, 3)})
        need(p.returncode == 0 and p.stdout == expected and not p.stderr, 'SMOKE_FAILED')
    return records


def run_transaction(base, progress_type, report):
    # RPM scriptlet errors can be nonfatal to the API call; never discard that evidence.
    report['transaction_error_count'] = 0
    class Progress(progress_type):
        def error(self, _message):
            report['transaction_error_count'] += 1
    base.do_transaction(display=Progress())
    report['transaction_returned'] = True
    need(report['transaction_error_count'] == 0, 'TRANSACTION_CALLBACK_ERROR')


def execute(dependency, dnf, rpm, expected, directory, report):
    report['stage'] = 'baseline'
    report['rpm_before'] = dependency.rpm_state(rpm)
    report['configuration_before'] = dependency.configuration_state()
    need(report['rpm_before'] == expected['baseline_rpm'] and
         report['configuration_before'] == expected['baseline_configuration'], 'BASELINE_CHANGED')
    before = inventory(rpm)
    report['stage'] = 'resolve'
    with dnf.Base() as base:
        baseline, enabled, substitutions = dependency.configure(base, directory, True)
        need(base.conf.installroot == '/' and set(base.conf.tsflags) <= {'nodocs'} and not base.conf.downloadonly
             and base.conf.gpgcheck and base.conf.sslverify, 'DNF_POLICY')
        report['rpm_tsflags'] = list(base.conf.tsflags)
        report['substitutions'] = substitutions
        base.fill_sack(load_system_repo=True, load_available_repos=True)
        for name in dependency.PACKAGES:
            if not list(base.sack.query().installed().filter(name=name)):
                base.install(name, strict=True)
        base.resolve(allow_erasing=False)
        packages = list(base.transaction.install_set)
        install = dependency.rows(packages)
        remove = dependency.rows(base.transaction.remove_set)
        report['stage'] = 'plan_check'
        check_plan(install, remove, expected, rpm.labelCompare)
        allowed = (dnf.transaction.PKG_INSTALL, dnf.transaction.PKG_UPGRADE,
                   dnf.transaction.PKG_UPGRADED)
        need(all(item.action in allowed for item in base.transaction), 'TRANSACTION_ACTION')
        report['transaction_plan_matches_ci416'] = True
        report['plan'] = {'install_set': install, 'remove_set': remove}
        download_and_verify(base, packages, report, dependency)
        report['stage'] = 'transaction'
        report['transaction_started'] = True
        run_transaction(base, dnf.callback.TransactionProgress, report)
    report['stage'] = 'rpm_check'
    after = inventory(rpm)
    report['delta'] = check_delta(before, after, expected)
    report['rpm_after'] = dependency.rpm_state(rpm)
    report['configuration_after'] = dependency.configuration_state()
    need(report['configuration_before'] == report['configuration_after'], 'CONFIGURATION_CHANGED')
    need(set(dependency.PACKAGES) <= {r['name'] for r in after}, 'RPM_DELTA')
    report['candidates_present'] = list(dependency.PACKAGES)
    report['stage'] = 'smoke'
    report['smoke'] = []
    smoke(directory, report['smoke'])
    report.update(stage='finished', status=SUCCESS)


def main(dependency, expected):
    report = {'schema': SCHEMA, 'status': 'INCOMPLETE', 'stage': 'identity',
              'rpm_downloaded': False, 'all_signatures_verified': False,
              'transaction_started': False, 'transaction_returned': False,
              'ruby_build_verified': False, 'p1_03_complete': False, 'phase1_complete': False,
              'imported_key_fingerprints': []}
    started = time.monotonic()
    def expired(_sig, _frame):
        raise Stop('TIME_LIMIT')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(900)
    try:
        need(os.environ.get('RUBY_P1_INSTALL_PROBE') == 'r27' and os.getuid() == 0
             and platform.system() == 'Linux' and platform.machine() == 'x86_64'
             and platform.python_version() == '3.9.19' and Path('/.dockerenv').is_file(), 'IDENTITY')
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                       if '=' in line and not line.startswith('#'))
        need(release.get('ID', '').strip('"') == 'centos' and
             release.get('VERSION_ID', '').strip('"') == '9', 'IDENTITY')
        need(not any(k.lower().endswith('_proxy') and v for k, v in os.environ.items()), 'DNF_POLICY')
        space = os.statvfs('/')
        report['root_free_bytes_before'] = space.f_bavail * space.f_frsize
        need(report['root_free_bytes_before'] >= MIN_FREE, 'SPACE_LOW')
        with dependency.silent_dependencies():
            import dnf
            import dnf.transaction
            import dnf.callback
            import rpm
            need(str(dnf.__version__) == '4.14.0' and str(rpm.__version__) == '4.16.1.3', 'IDENTITY')
            with tempfile.TemporaryDirectory(prefix='ruby-p1-install-', dir='/tmp') as directory:
                execute(dependency, dnf, rpm, expected, directory, report)
    except Exception as error:
        report['status'] = 'INCOMPLETE'
        report['reason'] = str(error) if type(error) is Stop else 'API_OR_RUNTIME_ERROR'
        report['error_kind'], report['errno'] = dependency.exception_codes(error)
    finally:
        signal.alarm(0)
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == SUCCESS else 3


if __name__ == '__main__':
    # These are injected by the hash-checked host bundle, not read from environment variables.
    raise SystemExit(main(_dependency, _expected))

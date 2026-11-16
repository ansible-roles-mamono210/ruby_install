"""r34: fixed CI430 RPM transaction and a Rust compiler smoke test."""
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile
import time

SCHEMA = 'ruby-p1-rust-install-container-r34'
SUCCESS = 'RUST_INSTALLED_AND_COMPILER_CHECKED'
RUST_HOST = 'x86_64-unknown-linux-gnu'
RUST_NAMES = ('rust_version', 'rust_compile', 'rust_program')
STAGES = ('identity', 'baseline', 'resolve', 'plan_check', 'download', 'signatures',
          'transaction', 'rpm_check', 'smoke', 'rust_smoke', 'finished')
RUST_SOURCE = 'fn main() { let v = vec![20, 22]; assert_eq!(v.iter().sum::<i32>(), 42); println!("RUST_COMPILER_OK"); }\n'


class Stop(Exception):
    pass


def need(value, reason):
    if not value:
        raise Stop(reason)


def parse_version(text, version):
    lines = text.splitlines()
    need(bool(lines) and lines[0].startswith('rustc ' + version + ' '), 'RUST_VERSION')
    pairs = [line.split(': ', 1) for line in lines[1:] if ': ' in line]
    need(len({key for key, _ in pairs}) == len(pairs), 'RUST_VERSION')
    values = dict(pairs)
    need(values.get('release') == version and values.get('host') == RUST_HOST, 'RUST_VERSION')
    return {'release': version, 'host': RUST_HOST}


def rust_smoke(directory, expected, report):
    selected = [r for r in expected['install_set'] if r['name'] == 'rust']
    need(len(selected) == 1 and selected[0]['arch'] == 'x86_64', 'RUST_VERSION')
    version = selected[0]['version']
    source, program = Path(directory) / 'rust_probe.rs', Path(directory) / 'rust_probe'
    source.write_text(RUST_SOURCE)
    commands = [
        ('rust_version', ['/usr/bin/rustc', '--version', '--verbose']),
        ('rust_compile', ['/usr/bin/rustc', '--edition=2021', '-C', 'opt-level=0',
                          str(source), '-o', str(program)]),
        ('rust_program', [str(program)])]
    report['rust_smoke'] = []
    for name, argv in commands:
        started = time.monotonic()
        p = subprocess.run(argv, capture_output=True, text=True, timeout=90, check=False,
                           env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': directory})
        match = False
        parsed = None
        if p.returncode == 0 and not p.stderr and len(p.stdout.encode()) <= 65536:
            if name == 'rust_version':
                try:
                    parsed = parse_version(p.stdout, version)
                    match = True
                except Stop:
                    pass
            else:
                match = p.stdout == ('' if name == 'rust_compile' else 'RUST_COMPILER_OK\n')
        report['rust_smoke'].append({'name': name, 'returncode': p.returncode,
            'stderr_bytes': len(p.stderr.encode()), 'output_match': match,
            'elapsed_seconds': round(time.monotonic() - started, 3)})
        need(p.returncode == 0 and not p.stderr and match, 'RUST_SMOKE_FAILED')
        if parsed:
            report['rust_version'] = parsed
    report['rust_compiler_checked'] = True


def execute(installer, dependency, dnf, rpm, expected, directory, report):
    # Reuse the hash-pinned transaction, signature, exact delta and C smoke checks.
    # The reused function's historical field name is relabelled to its actual input.
    try:
        installer.execute(dependency, dnf, rpm, expected, directory, report)
    finally:
        if 'transaction_plan_matches_ci416' in report:
            report['transaction_plan_matches_ci430'] = report.pop('transaction_plan_matches_ci416')
    report.update(status='INCOMPLETE', stage='rust_smoke', rust_installed=True)
    rust_smoke(directory, expected, report)
    report.update(stage='finished', status=SUCCESS)


def main(installer, dependency, expected):
    report = {'schema': SCHEMA, 'status': 'INCOMPLETE', 'stage': 'identity',
              'plan_reference': 'CI430', 'rust_installed': False, 'rust_compiler_checked': False,
              'rpm_downloaded': False, 'all_signatures_verified': False,
              'transaction_started': False, 'transaction_returned': False,
              'ruby_build_verified': False, 'p1_03_complete': False, 'p1_04_complete': False,
              'phase1_complete': False, 'imported_key_fingerprints': []}
    started = time.monotonic()
    def expired(_sig, _frame):
        raise Stop('TIME_LIMIT')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(900)
    try:
        need(os.environ.get('RUBY_P1_RUST_INSTALL_PROBE') == 'r34' and os.getuid() == 0
             and platform.system() == 'Linux' and platform.machine() == 'x86_64'
             and platform.python_version() == '3.9.19' and Path('/.dockerenv').is_file(), 'IDENTITY')
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                       if '=' in line and not line.startswith('#'))
        need(release.get('ID', '').strip('"') == 'centos' and
             release.get('VERSION_ID', '').strip('"') == '9', 'IDENTITY')
        need(not any(k.lower().endswith('_proxy') and v for k, v in os.environ.items()), 'DNF_POLICY')
        space = os.statvfs('/')
        report['root_free_bytes_before'] = space.f_bavail * space.f_frsize
        need(report['root_free_bytes_before'] >= installer.MIN_FREE, 'SPACE_LOW')
        with dependency.silent_dependencies():
            import dnf
            import dnf.transaction
            import dnf.callback
            import rpm
            need(str(dnf.__version__) == '4.14.0' and str(rpm.__version__) == '4.16.1.3', 'IDENTITY')
            with tempfile.TemporaryDirectory(prefix='ruby-p1-rust-install-', dir='/tmp') as directory:
                execute(installer, dependency, dnf, rpm, expected, directory, report)
    except Exception as error:
        report['status'] = 'INCOMPLETE'
        allowed = installer.REASONS | {'RUST_VERSION', 'RUST_SMOKE_FAILED'}
        report['reason'] = (str(error) if type(error) in (Stop, installer.Stop)
                            and str(error) in allowed else 'API_OR_RUNTIME_ERROR')
    finally:
        signal.alarm(0)
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == SUCCESS else 3


if __name__ == '__main__':
    raise SystemExit(main(_installer, _dependency, _expected))

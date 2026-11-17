[![CircleCI](https://dl.circleci.com/status-badge/img/gh/ansible-roles-mamono210/ruby_install/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/ansible-roles-mamono210/ruby_install/tree/main)

# ruby_install

A development snapshot of specifications and evaluation tooling for a
future Ruby installation Role on CentOS Stream 9.

> **Development status:** the v1.0.0 contract below describes the implementation
> target. The current Role in `tasks/main.yml` and `defaults/main.yml` still uses
> the earlier interface and does not implement this contract. Evaluation scripts
> under `scripts/p1/` are separate from the Role. Their passing results do not
> establish Role installation, idempotence, or release readiness. The badge above
> reports the `main` branch, not completion of the v1.0.0 contract.

## v0.1.0 development snapshot

**Preparation status: not published; final candidate SHA and fixed-image CI pending.**
v0.1.0 fixes the Phase 1 specification, evaluation tooling and historical
evidence. The included legacy Role does not implement the new contract.
The first planned installation-capable version under that contract is v0.2.0.
Do not run this snapshot as an implementation of the new public variables,
verified acquisition, managed-prefix protection or idempotence requirements.

- [Release notes and candidate checks](docs/releases/v0.1.0.md)
- [Phase 1 evidence, fixed source commits and limits](docs/p1-evidence.md)
- [Changelog](CHANGELOG.md)

To inspect the specification baseline now, retrieve its full commit in a new
directory. This command retrieves the pre-release-preparation baseline, not a
published v0.1.0 or the final candidate:

```sh
git clone https://github.com/ansible-roles-mamono210/ruby_install.git ruby-install-spec
cd ruby-install-spec
git checkout --detach 55a7ebfa6c6358ea03563d9ab6741921b2be03dc
git rev-parse HEAD
```

Candidate checks use the complete candidate SHA, record file hashes and retrieve
that SHA independently. After publication, the tag must be compared with that
approved SHA before using the snapshot. No `v0.1.0` tag is claimed to exist here.
Metadata does not advertise a tested minimum Ansible version or general EL
support. Omitting those fields does not imply support for every version.
The fixed environments below describe evaluations, not legacy Role compatibility.

## v1.0.0 contract

This section consolidates the adopted technical requirements for v1.0.0. Its
source is Redmine project 419, `20261108_ruby_100_roadmap_chatgpt_002_contract`
version 12, sections 14–17. Later explicit decisions take precedence over
earlier candidate values and historical status descriptions. The Roadmap,
`20261108_ruby_100_roadmap_chatgpt_001_draft` version 13, owns phase order and
the staged release scope. This README is the repository
destination for the technical contract; source code and test evidence determine
what has actually been implemented and verified.

### Scope and execution requirements

The implementation target is CentOS Stream 9 on x86_64, using ansible-core 2.21.6,
controller Python 3.14.10, target Python 3.9.19, and the Role dependency
`community.general` 13.5.1. These are the selected validation versions; they are
not a claim of successful Role execution across all other versions. The Role
does not install or replace the controller's Python or Ansible environment.

The calling playbook must gather distribution, major version, architecture and
other required facts, and provide root-equivalent privileges with `become` where
needed. Unsupported targets, insufficient privileges, invalid inputs and unsafe
existing state must stop with an identifiable reason before host changes.
Rocky Linux and AlmaLinux are not implicitly accepted as CentOS Stream 9.

One dedicated prefix holds one Ruby version. Its default is `/opt/ruby`.
OS-provided Ruby may coexist outside that prefix if the managed paths and public
command paths do not conflict. Automatic upgrade, downgrade, repair, uninstall,
adoption of unmanaged Ruby, migration from `/usr/local`, version switching,
rbenv/RVM management, ARM, Windows, macOS, Ruby application migration and Galaxy
publication are outside v1.0.0.

### Public variables

These are the v1.0.0 names and defaults to implement, not the current defaults.

| Variable | Type | Default | Meaning |
| --- | --- | --- | --- |
| `ruby_install_version` | string | `"3.4.12"` | Full stable version in the `3.4.N` or `4.0.N` series |
| `ruby_install_prefix` | string | `"/opt/ruby"` | Dedicated absolute installation path; one version per prefix |
| `ruby_install_download_url` | string | `""` | Empty derives the official tar.gz URL from the version; an explicit URL requires an explicit checksum |
| `ruby_install_download_checksum` | string | `""` | `sha256:` followed by 64 hexadecimal digits; empty is allowed only for a registered version with an automatically derived URL |
| `ruby_install_documentation` | boolean | `true` | Install Ruby's standard RDoc/ri documentation |
| `ruby_install_create_symlinks` | boolean | `false` | Opt in to publishing selected commands under `/usr/local/bin` |
| `ruby_install_symlink_commands` | list of strings | `["ruby", "gem", "bundle", "bundler", "irb", "erb", "rdoc", "ri", "rake"]` | Select only these nine command names; no duplicates, path separators or unknown names; nonempty when links are enabled |
| `ruby_install_build_jobs` | integer | `1` | Build parallelism, at least 1; boolean is not an integer input; installation is sequential |
| `ruby_install_workspace` | string | `"/tmp"` | Existing writable parent for a private child directory created for each new installation |
| `ruby_install_keep_build_workspace` | boolean | `false` | Keep that child directory after success; failure retains diagnostic material regardless of this value |

No implicit type conversion is allowed. Empty versions, non-string versions,
`latest`, previews, version ranges and other Ruby series are rejected before
changes. A syntactically accepted, unregistered patch version is not a tested
version; its required configure controls must also be identifiable.

Use YAML variables, JSON extra vars, or a YAML/JSON vars file to preserve types.
The argument fragment `-e '{"ruby_install_build_jobs":4,"ruby_install_documentation":false}'`
preserves an integer and a boolean. The visually similar `-e ruby_install_build_jobs=4`
and `-e ruby_install_documentation=false` pass strings and must be rejected.

### Migration from earlier names

Each of the following five old names, if visible when this Role executes, must
cause a pre-change error with its replacement or removal reason, including an
empty/null value or simultaneous old and new names. This applies regardless of
whether the visible variable came from inventory, another Role, a registered
result or an explicit Role argument. The Role does not infer the caller's intent
from the variable's origin. There are no compatibility aliases, automatic value
selection or conversion. Actual visibility depends on Ansible scoping; this is
not a claim that every other Role's variables are always exposed.

| Old name | Origin | Replacement or disposition |
| --- | --- | --- |
| `workspace` | Earlier implementation | `ruby_install_workspace`; each run uses a private child, not a shared fixed extraction directory |
| `ruby_version` | Earlier implementation | `ruby_install_version` |
| `ruby_download_url` | Earlier implementation | `ruby_install_download_url`; automatic derivation replaces an independent fixed default URL |
| `ruby_make_prefix` | Earlier implementation | Removed; use `ruby_install_prefix`. Do not convert `/usr/local/bin/ruby` into a directory prefix automatically |
| `ruby_source_configure_command` | Earlier README only | Removed; arbitrary shell/configure commands are not a public API |

Five names appeared only in an earlier contract proposal:
`ruby_download_checksum`, `ruby_create_symlinks`, `ruby_symlink_commands`,
`ruby_build_jobs` and `ruby_keep_build_workspace`. Their presence alone is no
longer rejected. They are neither public inputs nor aliases and do not configure
this Role. Use the corresponding `ruby_install_` names.

`ruby_install_prefix` and `ruby_install_documentation` retain their adopted
names. When the Role implementation changes, migration notes, CHANGELOG, examples
and the input-rejection tests must change together. This documentation step
does not modify existing callers or implement old-name rejection.

### Source selection and acquisition

The following tar.gz artifacts are fixed by the adopted contract. Other archive
formats must not reuse these checksums.

| Ruby | Use | URL | SHA-256 |
| --- | --- | --- | --- |
| 3.4.12 | Default and required matrix | https://cache.ruby-lang.org/pub/ruby/3.4/ruby-3.4.12.tar.gz | `5e5d85ad93b0adcccbad47733680f4892bd0078e3342437f7babce01c1872479` |
| 4.0.9 | Additional required matrix | https://cache.ruby-lang.org/pub/ruby/4.0/ruby-4.0.9.tar.gz | `c35350682ff050b79702d57ade4516e7336063f510155d19fb2fb5b3f3909511` |

An empty URL is derived from the requested full version and its major/minor
series. An empty checksum is resolved from this table only when the URL is
automatic and the version is registered here. An explicit URL always requires
an explicit matching checksum, even for a registered version. An unregistered
patch version also requires an explicit checksum. A supplied checksum for a
registered version at its official URL must match the fixed official value.

Only HTTPS URLs without embedded credentials are accepted. Certificate and
hostname verification are mandatory; there is no public option to disable them.
All redirects, including HTTPS-to-HTTPS redirects, must fail without contacting
the redirect destination. A URL must serve the archive directly. An earlier
observation of an official URL does not guarantee its future behavior.

Proxy use is explicitly unsupported through the first stable release.
The Role must not inherit an environment proxy; a proxy-only network cannot use
this acquisition path. Supporting proxies later requires a separate contract
decision. The adopted Phase 3 acquisition route is:

1. Download the actual file with `ansible.builtin.uri`, `follow_redirects: none`,
   `validate_certs: true` and HTTP 200 as the accepted result. Set
   `use_proxy: false`, `use_netrc: false` and `decompress: false` explicitly.
   A preliminary URL check does not replace control of the actual download.
2. Use `ansible.builtin.stat` with `checksum_algorithm: sha256` and `follow: false`
   to obtain file attributes and its digest. Use `ansible.builtin.assert` to
   require a regular, non-symlink file and the expected digest.
3. Check the expected `ruby-VERSION` archive structure and reject absolute paths,
   parent traversal and links escaping the private workspace before extraction.
4. Only then extract, build and install into the managed prefix.

The `uri` → `stat` → `assert` route passed the bounded evaluation described below;
its selection was adopted in contract section 15 and supplemented in section 16.
Production Role integration remains unimplemented. The evaluation's
fixture gate marker is not an installation record and must not replace archive
validation or production installation checks. Archive validation remains a
Phase 3 implementation responsibility. No `follow_redirects` option is passed
to `get_url`.

Checksum or structure failure must prevent extraction, build and Ruby
installation. This is not rollback of earlier dependency installation or CRB
changes. A checksum identifies bytes; it does not establish that an arbitrary
user-selected source is trustworthy.

### Paths, workspace and capacity

On every run, validate types, absolute paths, normalization and lexical
prefix/workspace equality or containment. Reject a prefix that is a regular file,
a final-component symlink or a shared base such as `/`, `/usr`, `/usr/local` or
`/opt`. The prefix, its trusted existing parents, `bin/ruby`, the installation
record and managed code/library paths loaded by health checks must be owned by
root and not writable by group or others. Apply the same criteria to a dedicated
empty prefix. Establish safety before executing existing Ruby as root.

Parent symlinks are allowed only after checking both the parent containing the
link and the resolved path. Reject loops, unresolved paths, unsafe permissions
or identity changes during observation. A safe parent symlink does not permit a
symlink at the final prefix component.

Only a new installation requires workspace environment checks: existing
directory, write access, resolved-path non-overlap, noexec and usable capacity.
Do not create the workspace parent automatically. A root-owned sticky shared
parent such as `/tmp` is allowed; its private child must exclude other writers.
Inspect `statvfs` flags at the actual workspace parent for `ST_NOEXEC` before
dependencies, CRB changes or child creation. Stop on noexec or an inability to
obtain the required observation, without changing mounts or bypassing noexec.
A general mountinfo parser is not required. Absence of this flag does not prove
that SELinux or every other execution constraint permits a build.

A healthy identical rerun skips workspace existence, write access, noexec,
capacity and resolved-path checks because it does not use a workspace. Static
input checks and prefix, record, Ruby and link protection still apply.

For a new installation, use a private child directory that other users cannot
write. Do not trust or reuse shared tarballs, extracted trees or old build output.
The Role may clean only the child directory it created for that run.

| Result | Workspace behavior |
| --- | --- |
| Success, keep flag false | Remove this run's child directory |
| Success, keep flag true | Retain it and report its location |
| Failure | Retain diagnostic workspace/logs and report the location and failure stage |
| Healthy installation with identical build contract | Create no build workspace |

The adopted free-space starting thresholds are:

| Filesystem placement | Required free space for workspace and Ruby prefix growth |
| --- | --- |
| Same filesystem | 2 GiB total, counted once |
| Different filesystems | 2 GiB on the workspace filesystem and 512 MiB on the prefix filesystem |

Check usable space with the actual execution identity at the workspace parent
and the prefix's resolved filesystem; if the prefix is absent, use its existing
parent. Compare `st_dev`: equal values use the combined 2 GiB threshold once;
different values use the two thresholds separately. Stop if required observations
cannot be obtained. Different device IDs do not prove independent physical
capacity. This preflight check does not attempt to predict every quota, overlay
or tmpfs constraint.
Check before starting a new installation and again after installing dependencies,
before source acquisition. If the second check fails, do not claim dependencies
were rolled back. Do not require the new-build allowance for a healthy no-op run.

These thresholds add margin to sampled evaluation use; they do not guarantee
capacity under quotas, compression, other block sizes or different layouts.
OS/RPM data, DNF caches, container layers, artifacts, retained failure workspaces
and other processes need separate space, added on any shared filesystem. Never
delete previous failure workspaces to make room automatically. Free tmpfs space
does not establish available physical RAM.

### Dependencies and build policy

Only a permitted new installation may install required packages with
`state: present`. The directly required packages are `gcc`, `make`, `tar`,
`gzip`, `ca-certificates`, `openssl-devel`, `libyaml-devel`, `zlib-devel` and
`libffi-devel`. This list does not exclude packages pulled in as dependencies.

If required development packages cannot be resolved with CRB disabled, install
`dnf-plugins-core` as needed and enable CRB. Do not automatically disable it
afterward. Do not remove existing packages or update the whole host. Rust is not
a Role dependency; neither are the earlier direct requirements `bzip2`, `wget`,
`git`, `gdbm-devel`, `ncurses-devel` and `readline-devel`. A healthy same-contract
installation must not install dependencies or change CRB.

| Target | Configure/build contract |
| --- | --- |
| Both fixed Ruby versions | Explicit `--prefix`, `--enable-shared`, `--enable-rpath`, `--enable-option-checking=fatal`, `--disable-install-capi` |
| Ruby 3.4.12 | Explicit `--disable-yjit` and `--disable-rjit` |
| Ruby 4.0.9 | Explicit `--disable-yjit` and `--disable-zjit` |
| Documentation true | Explicit `--enable-install-doc` and `--enable-install-rdoc` |
| Documentation false | Add `--disable-install-doc`; omit standard document generation/installation |
| Parallelism | Default build jobs 1; sequential installation |

JIT must be disabled at build and runtime, regardless of whether Rust is already
installed. For other accepted patch versions, verify the relevant controls and
reject unknown configure options instead of ignoring them. Do not expose an
arbitrary configure string or shell command.

The managed Ruby and required extensions must load shared libraries when invoked
by absolute path without adding `LD_LIBRARY_PATH` or changing `/etc/ld.so.conf.d`.
Prevent inherited `RUBYOPT`, `RUBYLIB`, `GEM_HOME`, `GEM_PATH`, `CONFIGURE_ARGS`,
`MAKEFLAGS` and similar build/runtime inputs from silently changing the build
contract. Control task-local environments without rewriting host-wide settings.

Documentation defaults to standard RDoc/ri data; extra C API/HTML documentation
is outside scope. Turning documentation off does not remove `ri`/`rdoc` commands
or change later user-invoked `gem install` behavior. Existing documentation
settings belong to the recorded build contract, so changing them for an installed
prefix must stop rather than add/remove documents or rebuild silently.

### Installation-state decisions

Inspect `<prefix>/bin/ruby`, not whichever Ruby is first on PATH. Require both a
completed installation record inside that prefix and successful health checks of
the actual files, version, `RbConfig` paths and required functionality. The record
must identify the version, prefix, source SHA-256, shared-library/JIT policy and
documentation setting. Its private filename and representation remain
implementation choices. Finalize it only after installation and health checks
succeed; a record alone never proves a healthy installation. Phase 2 defines
the common record representation, validation and assembly logic; test fixtures
use that same logic. Phase 3 writes the real prefix's completed record after
successful installation and complete post-installation checks. Final identical
rerun acceptance requires a record created by the Role, not only fixture records.

| Check occasion | Required scope |
| --- | --- |
| Identical rerun | Requested version, RbConfig placement, shared library, openssl/psych/zlib, JIT and standard-documentation build settings |
| Immediately after installation | Complete check including all nine commands, Fiddle, documentation on/off data and managed ri access when enabled; Phase 3 responsibility |
| Before link publication | Selected command sources only, in addition to prefix/build-state checks |

Do not pin every command version or inspect all ri data on each rerun. Ordinary
`gem install` or `bundle install` changes alone do not invalidate an installation.
Broken core functionality, a record/build mismatch or a missing selected link
source still causes a stop. Runtime-disabled JIT alone does not prove that JIT
was disabled at build time.

| Observed state | Required behavior |
| --- | --- |
| Prefix absent; inputs, environment and publication paths valid | Install into the new dedicated prefix |
| Dedicated empty prefix with suitable ownership, permissions and parent path | Permit new installation; unrelated content instead causes a stop |
| Same version/build contract, valid record and healthy files | No download, configure, make, dependency installation, CRB change or workspace creation; inspect links separately |
| Same version but source digest, shared-library/JIT policy or documentation differs | Stop before host changes; do not rebuild or adjust documents |
| Ruby exists but record is missing, unreadable, incomplete or inconsistent with placement | Stop; do not adopt unmanaged files |
| Valid record exists but Ruby is missing | Stop as incomplete installation and preserve files |
| Different version in the same prefix | Stop; no upgrade, downgrade or overwrite |
| Partial, corrupt, non-executable installation or missing required functionality | Stop; no automatic repair |
| OS Ruby outside the managed prefix without path conflicts | Preserve it and allow coexistence |
| Conflicting paths, unsupported environment or invalid inputs | Stop before dependencies, CRB or managed-path changes |
| A different new prefix is requested while an old prefix remains | Assess the new prefix independently; preserve old prefix/links and stop on publication conflicts |
| Build or installation fails partway | Report failure and possible partial prefix; do not finalize a successful record; a later run must reject incomplete state |

When observations overlap, use the first applicable result in this order.
Do not execute invalid/untrusted files to classify a later condition. These are
contract categories, not names of an already implemented module API.

| Order | Observation | Primary result |
| --- | --- | --- |
| 1 | Invalid facts, OS, privileges, input types/values, old names or unsupported feature request | Applicable prerequisite/input error |
| 2 | Unsafe or unobservable prefix/required path | Path/safety error |
| 3 | Absent or suitable dedicated empty prefix | New-install candidate; continue with workspace, capacity and publication/residual checks |
| 4 | Nonempty prefix with no record | Record error if Ruby exists, otherwise incomplete installation; do not execute/adopt it |
| 5 | Unreadable or malformed record | Record error |
| 6 | Valid record but missing Ruby | Incomplete installation |
| 7 | Recorded version differs | Version mismatch |
| 8 | Recorded source, placement or build settings differ | Build-contract mismatch |
| 9 | Safe executable observation fails, times out or returns invalid data | Health-check failure |
| 10 | Observed version differs from request/record | Version mismatch |
| 11 | Observed placement or build settings differ | Build-contract mismatch |
| 12 | Required library/function check fails | Health-check failure |
| 13 | Healthy identical installation | Proceed to link/residual checks; no build, dependencies or workspace |

Link settings are separate from the build contract; a link-only change must not
rebuild Ruby. Concurrent installations into the same prefix are unsupported.
Detect changes after conflict inspection and immediately before publication.
Installation and link creation are not promised to be atomic or automatically
rolled back.

Recovery is a deliberate human operation: confirm use and ownership, back up
needed data/logs, identify and remove only the relevant public links, then remove
only the intended prefix and retained private workspace if reinstallation is
required. Recheck inputs before rerunning. Removing a prefix alone does not clean
links/workspaces, and this is not a rollback of packages or CRB. Do not apply a
cleanup command to all of `/tmp`, another prefix or unrelated files.

### Command publication

Links are disabled by default. In v0.2.0, requesting links must stop as
unsupported before host changes, while disabled-link residual checks still apply.
Link creation starts with v0.3.0. When explicitly enabled, publish selected allowed
commands to `/usr/local/bin/<command>`, resolving to the corresponding healthy
`<prefix>/bin/<command>`. Inspect all selected sources/destinations before creating
any link. Do not install additional gems to conceal a missing command.

| Setting/state | Required behavior |
| --- | --- |
| Links disabled and no applicable existing publication | Leave link publication paths unchanged; a permitted new install may still install dependencies or enable CRB |
| Links enabled, all sources healthy and destinations absent | Create after checking the entire set |
| Existing link resolves to the correct command in this prefix | Reuse without unnecessary changes |
| Regular file, another Ruby's link, broken link or unresolvable state | Stop; no forced replacement or automatic deletion |
| Selected source missing or non-executable | Stop before creating links |
| Enabled → disabled with links to this prefix remaining | Stop and request manual removal |
| Command list reduced with removed commands still published | Stop and request manual removal |
| Creation fails or a conflict appears partway | Stop and report created/not-created links; no automatic rollback |

For disabled/reduced lists, inspect the nine allowed public names and their
resolved targets. Do not rely only on an installation record's list or infer who
created a link. Do not alter PATH, profiles, sudoers or `secure_path`.
Use `/opt/ruby/bin/ruby` (or the configured prefix) explicitly; `ruby` and
`sudo ruby` may resolve to different installations.

From v0.2.0, callers must migrate to absolute paths under `<prefix>/bin` or
explicitly manage their task's PATH. This also applies to commands added later by
gems, such as `passenger-install-apache2-module`: they are outside the nine allowed
public names. Enabling links in v0.3.0 does not publish those extra commands or
automatically update Redmine/Passenger Roles and playbooks.

The pinned target's pre-fixture baseline in
[CI396, job1604](https://app.circleci.com/pipelines/github/ansible-roles-mamono210/ruby_install/396/workflows/882e5191-bc2c-46bb-83d5-8ef853c942a6/jobs/1604)
measured the following effective paths:

| Invocation | Observed PATH |
| --- | --- |
| Container `docker exec` as root | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` |
| Root invoking `sudo -n -H` | `/sbin:/bin:/usr/sbin:/usr/bin` |

None of the nine Ruby commands resolved in either baseline. In particular, the
observed sudo path excludes `/usr/local/bin`; enabling public links alone does
not make `sudo ruby` resolve there. These are effective container PATH results,
not a reading of a production `secure_path` configuration or a universal CentOS
default. The separate non-root become check used a disposable test user and sudo
rule; it does not establish stock non-root privileges or production become setup.

### Examples for the future implementation

These examples describe v1.0.0 inputs. Do not use them as proof that the current
Role supports the variables or preserves the boundaries above.

```yaml
---
- name: Install the managed Ruby
  hosts: all
  gather_facts: true
  become: true
  roles:
    - role: ruby_install
      vars:
        ruby_install_version: "3.4.12"
        ruby_install_prefix: /opt/ruby
        ruby_install_documentation: true
        ruby_install_create_symlinks: false
        ruby_install_build_jobs: 1
        ruby_install_workspace: /tmp
```

For a Redmine caller, set `ruby_install_documentation: false` before the initial
installation. This does not alter an existing Redmine playbook or convert an
already-installed prefix with documentation enabled. Use `/opt/ruby/bin/ruby --version`
to inspect the managed executable; changing application execution paths is a
separate migration task.

Check mode is limited to inputs and existing-state checks. It does not promise
that a new build would succeed or that downloaded bytes have been verified.

### Validation baseline and evidence boundaries

| Purpose | Pinned image | Measured versions |
| --- | --- | --- |
| Role/Molecule/syntax controller | `ghcr.io/docker-images-mamono210/circleci-executors/molecule-docker@sha256:a80f2c478e9e183cdd782f8cdff79d1025cdc5291190e360898738fd8e6f7f41` | Python 3.14.10; core 2.21.6; Molecule/plugins 26.11.0; community.general 13.5.1; ansible.posix 2.2.2; community.docker 5.4.0 |
| Target | `ghcr.io/docker-images-mamono210/ansible-test/centos-stream9@sha256:96fbd1eac7c972466192da5183e80deeacd226332265d1698b2581bf7666ccd2` | CentOS Stream 9, x86_64, Python 3.9.19; amd64 manifest `sha256:04f9e631a4f0ba1cbf9b13c4b29d6e9f1b0f5365f661c5128c220d66d5870e92` |
| Supplementary lint | `ghcr.io/docker-images-mamono210/circleci-executors/ansible-lint@sha256:4ea7fe7ebbe7fd06bd5a7fc61b8931c3303a11c9bd4eb06431a810f5914b8718` | Python 3.14.3; ansible-lint 26.1.1; core 2.20.3; ansible-compat 25.12.0; ruamel.yaml 0.19.1; yamllint 1.38.0 |

`community.general` is a Role execution dependency. Molecule, its plugins,
`ansible.posix` for profiling and `community.docker` for Docker-based validation
belong to the test environment. Do not install the older molecule-docker driver
alongside the selected plugins. Lint's core 2.20.3 is not the Role execution
baseline; lint success cannot replace testing under core 2.21.6. Pinned-image
evidence covers transitive dependencies; this table is not an equivalent set of
unpinned pip installation instructions.

The adopted normal lint integration is `orbss/ansible-lint@1.0.0` with the pinned
lint image, whole-Role lint and the additional actual-file checker
`scripts/check_role_variable_names.py`. The checker verifies unchanged contents
in a temporary `roles/ruby_install` layout using all normal rules. Empty input,
invalid inputs and suppression-based false success must be rejected. Updating the
Orb alone, using only `--tags var-naming`, or skipping naming rules is insufficient.
This normal CI integration remains to be implemented.

The adopted normal `.yamllint` changes are
`comments.min-spaces-from-content: 1`, `comments-indentation: disable`,
`braces.max-spaces-inside: 1`, `octal-values.forbid-implicit-octal: true` and
`octal-values.forbid-explicit-octal: true`. Do not transfer the dedicated checker's
line-length exemption to normal lint or disable other rules under this decision.
The existing known-warning exception applies only to the fixed controller's
Collection-list observation, under the identity checks recorded in contract v9
section 13. It is not a blanket warning exemption for playbooks, lint or tests.

For v0.2.0, v0.3.0 and v1.0.0, the required Role matrix has six conditions,
each including installation,
functional verification and an identical second run:

| Ruby | Prefix | Standard documentation | Rust in test environment |
| --- | --- | --- | --- |
| 3.4.12 | `/opt/ruby` | On | Absent |
| 3.4.12 | Custom | Off | Absent |
| 3.4.12 | `/opt/ruby` | On | Present |
| 4.0.9 | `/opt/ruby` | On | Absent |
| 4.0.9 | Custom | Off | Absent |
| 4.0.9 | `/opt/ruby` | On | Present |

Rust-present conditions still require full builds and build/runtime JIT checks.
The six conditions are neither a complete Cartesian product nor six fixed CI
jobs. Preserve the four categories: trailing-whitespace, yamllint, ansible-lint
and molecule. Run the full matrix sequentially for final code-changing PR
candidates and release candidates for these implementation releases; separate
checks that do not require builds. The v0.1.0 evaluation snapshot has its own
limited acceptance scope below.

Additional required checks retain the contract's IDs. These are design
requirements, not names of existing Molecule scenarios or CI jobs:

| ID | Required coverage |
| --- | --- |
| T01–T03 | Both Ruby versions, default/custom prefix, version/path/RbConfig identity, healthy identical rerun without rebuild or other unnecessary changes |
| T04–T05 | Existing different/unmanaged/partial/broken/mismatched installations remain protected; OS Ruby coexists outside managed paths |
| T06 | Version/URL/checksum rules, actual byte verification and redirect rejection before destination requests, including HTTPS→HTTP and HTTPS→HTTP→HTTPS paths |
| T07–T08 | Link off/on/reuse/conflict, all sources checked first, disable/list reduction with residual links |
| T09 | Nine commands and gem basics; documentation on/off; managed `ri` reads standard Ruby class documentation when enabled; no external documentation/gems hide missing output |
| T10–T11 | openssl/psych/zlib and shared-library loading without environment rescue; build/runtime JIT disabled with and without Rust |
| T12–T14 | Owned-workspace success/failure handling, fixed-ref Role distribution, cleanup of test containers with required failure evidence retained |
| T15 | The five rejected old names, including externally visible definitions; wrong types, invalid versions, checksum/URL errors, command-list errors and unsafe paths; workspace environment failures for new installs and healthy-rerun controls that skip those checks |

Phase 2 integration tests are planned as a Molecule scenario, with unit tests
also running on target Python 3.9 and module discovery/lint checked in the fixed
environments. These scenarios and CI jobs are not implemented yet. Interim
preflight-only tests do not replace the normal four CI categories required by
v0.2.0 and later. A workflow that did not run is not a passing test.

The initial full-Role test planning basis is target CPU1, memory limit 2 GiB,
no additional swap, make jobs 1, one condition at a time and no automatic retries.
This does not limit the public build-jobs input to 1 or guarantee host RAM needs.
The initial planning allowance is 1500 credits and a 20-minute stop-decision
threshold per build condition. Before any run, check current pricing, balance,
resource class and the complete job estimate, and implement timeout/child-process
termination, failure evidence and cleanup. These values are not billing caps or
authorization to trigger CI or a combined budget for three releases. On OOM or
timeout, retain evidence and stop; do not silently reduce coverage or rerun.

#### Evaluation completed before Role implementation

As of 2026-11-17, evaluation scripts have established feasibility of the six build
conditions and the selected environment, dependency, noexec, naming and resource
conditions recorded in contract v9 section 14. They do not establish the Role's
state machine or idempotence. CI452 specifically detected four legacy variable
names in unchanged defaults and accepted the renamed control; it did not prove
that the current whole Role passes lint.

[CI454, job1633](https://app.circleci.com/pipelines/github/ansible-roles-mamono210/ruby_install/454/workflows/ed629854-a4b8-47ff-baf6-ef5ef4f2d7ef/jobs/1633/artifacts)
ran commit `0c8fbcc611271ea0c2e31bfe02615b05766e24af` and passed 16 real Ansible
acquisition cases: valid download, checksum mismatch, six redirect status codes
to each of HTTP and HTTPS, untrusted certificate and hostname mismatch. The
redirect codes were 300, 301, 302, 303, 307 and 308. Only the valid case reached
the fixture gate; all destination connection/request deltas were zero. The
controller and target containers and temporary TLS directory were cleaned up.
This was a loopback fixture, not a download/build of official Ruby through the
Role. Its artifact intentionally keeps `role_verified`, `p1_04_complete` and
`phase1_complete` false. The 582 local tests were separate from this CI job.

### Release and compatibility

Role release numbers are distinct from Ruby 3.4.12 or 4.0.9. The adopted
stages retain Phase 1–7 responsibilities; verification, documentation and
publication (Phases 5–7) apply to each release's scope.

| Planned Role release | Scope and acceptance boundary |
| --- | --- |
| v0.1.0 | Phase 1 specification/evaluation development snapshot. Reconciled specifications, fixed evaluation references, LICENSE/meta/CHANGELOG/Release Notes and fixed-ref retrieval. Explicitly label the included legacy Role and unimplemented new contract. Candidate documentation/static checks and affected evaluation regressions are required; unchanged evaluation sources/conditions may reference existing evidence at its original commit. No claim of real Role installation or full four-category contract compliance. |
| v0.2.0 | Phases 2+3: installation, complete post-install checks, Role-generated records, healthy identical rerun, invalid-state protection and owned workspace management. Six real Role conditions, normal four CI categories, applicable T01–T06 and T09–T15, T07 input validation and T08 disabled-link residual protection. Link-ON requests stop before changes. Include minimum manual recovery and migration instructions. |
| v0.3.0 | Phase 4: full T07/T08 link publication and failure handling; v0.2.0 regressions, six real Role conditions and normal four CI categories. Prove rerun/link addition using records actually written by v0.2.0. Extra gem commands remain outside publication scope. |
| v1.0.0 | Complete T01–T15, six real Role conditions, normal four CI categories, v0.2.0/v0.3.0 prefix/link compatibility, distribution and migration/recovery examples. Finalize the public contract without adding unrelated features to the completion criteria. |

Redmine Version identifiers are `0.1.0`, `0.2.0`, `0.3.0` and `1.0.0`, paired
with Git tags `v0.1.0`, `v0.2.0`, `v0.3.0` and `v1.0.0`. The 0.x versions use
GitHub Pre-release; v1.0.0 uses GitHub Release. These are planned identifiers,
not a claim that the corresponding objects exist. Tickets use target versions;
`release_tag` remains unused and Galaxy publication is deferred.

Phase 2 and Phase 3 share record assembly/validation and may be developed in
parallel. Their end-to-end installation/rerun acceptance is joined at v0.2.0.
Freeze the record format before v0.2.0 publication and verify compatibility in
later releases; do not publish a throwaway intermediate format. A preflight-only
intermediate Role is not an installation-capable release. Later functional
releases remain subsets of the final contract without temporary public inputs.

Public names, types, defaults, permitted values, semantics, supported environment,
state decisions and failure boundaries form the compatibility contract. From
v1.0.0, use a major release for incompatible changes, minor for compatible
additions or deprecation notices, and patch for compatible fixes. During 0.x,
state changes and migration impacts explicitly and preserve the adopted record
compatibility requirements. A Ruby patch update does not automatically make a
Role default-version change compatible, since it can stop an existing prefix.

Phase 1's technical completion was adopted in r51 (contract v10 / Roadmap v11).
The r55 decisions (contract v11 / Roadmap v12) supplement that specification;
this README incorporates them without reclassifying evaluation as Role proof.
Phase 2/3 implementation and real Role validation remain outstanding.

Before each publication, align that release's implementation claims, metadata,
examples, CHANGELOG, tests and release notes; verify the candidate's fixed-ref
distribution and then retrieval of the published tag in a separate directory.
P1-06 requires human confirmation of copyright ownership and code provenance,
and a finalized LICENSE before the first v0.1.0 publication, including a tag-only
publication. The holder confirmed the existing code was self-written; this
candidate includes the BSD-3-Clause LICENSE with the confirmed holder and year.
This completes the candidate's license preparation, not its release validation.
The v0.1.0 check configuration is described in the release notes. Its fixed
images, real execution results, budget and final candidate remain to be verified
before publication; local preparation is not completion of those conditions.
None of the evaluation evidence alone establishes release readiness.

## Earlier implementation snapshot

At evaluation commit `0c8fbcc611271ea0c2e31bfe02615b05766e24af`, the unchanged
`defaults/main.yml` contains these earlier values:

| Variable | Existing value |
| --- | --- |
| `workspace` | `/tmp` |
| `ruby_download_url` | `http://cache.ruby-lang.org/pub/ruby/3.2/ruby-3.2.3.tar.gz` |
| `ruby_version` | `3.2.3` |
| `ruby_make_prefix` | `/usr/local/bin/ruby` |

The earlier Role checks `ruby -v` via PATH, downloads without a checksum,
configures without an explicit prefix, passes uppercase `PREFIX` to make, and
creates six forced links under `/usr/bin`. DNF plugin/CRB handling is outside its
Ruby-installation guard. These observations explain the migration work; they are
not v1.0.0 guarantees. `ruby_source_configure_command` was documented but is not
used in the current tasks. The earlier README's `3.0/ruby-3.2.3.tar.gz` path did
not match the default's `3.2` path. Its `Requirements: None` statement is replaced
by the explicit requirements above.

## License

This source is licensed under [BSD-3-Clause](LICENSE).

Copyright (c) 2021 mamono210.

The holder confirmed that the existing code was self-written and selected the
initial-commit year for this notice. The repository's root commit is
[`83777ecb4b1daf1f033020ac65321d2d48701b90`](https://github.com/ansible-roles-mamono210/ruby_install/commit/83777ecb4b1daf1f033020ac65321d2d48701b90),
dated 2021-03-26. The LICENSE and metadata now use the same identifier, replacing
the earlier ambiguous labels. This license does not imply completion of the
new Role contract or publication of v0.1.0.

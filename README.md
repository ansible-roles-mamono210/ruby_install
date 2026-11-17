[![CircleCI](https://dl.circleci.com/status-badge/img/gh/ansible-roles-mamono210/ruby_install/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/ansible-roles-mamono210/ruby_install/tree/main)

# ruby_install

An Ansible role for installing Ruby from source on CentOS Stream 9.

> **Development status:** the v1.0.0 contract below describes the implementation
> target. The current Role in `tasks/main.yml` and `defaults/main.yml` still uses
> the earlier interface and does not implement this contract. Evaluation scripts
> under `scripts/p1/` are separate from the Role. Their passing results do not
> establish Role installation, idempotence, or release readiness. The badge above
> reports the `main` branch, not completion of the v1.0.0 contract.

## v1.0.0 contract

This section consolidates the adopted technical requirements for v1.0.0. Its
source is Redmine project 419, `20261108_ruby_100_roadmap_chatgpt_002_contract`
version 9, with the explicit updates in section 14 taking precedence over earlier
candidate values. The Roadmap, `20261108_ruby_100_roadmap_chatgpt_001_draft`
version 10, owns phase order and release scope. This README is the repository
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

Every old name below must cause a pre-change error with its replacement or
removal reason, including an empty value or simultaneous old and new names.
There are no compatibility aliases, automatic value selection or conversion.

| Old name | Origin | Replacement or disposition |
| --- | --- | --- |
| `workspace` | Earlier implementation | `ruby_install_workspace`; each run uses a private child, not a shared fixed extraction directory |
| `ruby_version` | Earlier implementation | `ruby_install_version` |
| `ruby_download_url` | Earlier implementation | `ruby_install_download_url`; automatic derivation replaces an independent fixed default URL |
| `ruby_make_prefix` | Earlier implementation | Removed; use `ruby_install_prefix`. Do not convert `/usr/local/bin/ruby` into a directory prefix automatically |
| `ruby_source_configure_command` | Earlier README only | Removed; arbitrary shell/configure commands are not a public API |
| `ruby_download_checksum` | Earlier contract proposal | `ruby_install_download_checksum` |
| `ruby_create_symlinks` | Earlier contract proposal | `ruby_install_create_symlinks` |
| `ruby_symlink_commands` | Earlier contract proposal | `ruby_install_symlink_commands` |
| `ruby_build_jobs` | Earlier contract proposal | `ruby_install_build_jobs` |
| `ruby_keep_build_workspace` | Earlier contract proposal | `ruby_install_keep_build_workspace` |

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

The evaluated Ansible route proposed for Phase 3 is:

1. Download the actual file with `ansible.builtin.uri`, `follow_redirects: none`,
   `validate_certs: true` and HTTP 200 as the accepted result. The evaluated route
   disables implicit proxy/netrc use and HTTP Content-Encoding decompression; it does not
   substitute a preliminary URL check for control of the actual download.
2. Use `ansible.builtin.stat` with `checksum_algorithm: sha256` and `follow: false`
   to obtain file attributes and its digest. Use `ansible.builtin.assert` to
   require a regular, non-symlink file and the expected digest.
3. Check the expected `ruby-VERSION` archive structure and reject absolute paths,
   parent traversal and links escaping the private workspace before extraction.
4. Only then extract, build and install into the managed prefix.

The `uri` → `stat` → `assert` route passed the bounded evaluation described below;
its selection for the Role is part of this README proposal. The evaluation's
fixture gate marker is not an installation record and must not replace archive
validation or production installation checks. Archive validation remains a
Phase 3 implementation responsibility. No `follow_redirects` option is passed
to `get_url`.

Checksum or structure failure must prevent extraction, build and Ruby
installation. This is not rollback of earlier dependency installation or CRB
changes. A checksum identifies bytes; it does not establish that an arbitrary
user-selected source is trustworthy.

### Paths, workspace and capacity

Normalize and validate absolute prefix/workspace paths and their resolved
locations. The managed areas must not overlap or contain one another. Reject a
prefix that is a regular file, a symlink, a shared base such as `/`, `/usr`,
`/usr/local` or `/opt`, or whose ownership, permissions or resolved path cannot be
established safely. An existing dedicated empty directory may be used only when
its ownership, permissions and parent path are suitable.

The workspace parent must already exist, be a directory and be writable by the
execution identity. Do not create it automatically. `/tmp` remains a valid
parent when these conditions are satisfied. Detect an applicable `noexec` mount
before dependency installation, CRB changes or workspace creation, and stop
with a reason. Do not change mount flags or work around this restriction.
Absence of `noexec` alone does not prove that a build will succeed.

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
parent. Do not infer filesystem identity from path strings or double-count bind
mounts/overlay storage. Stop if the relevant storage cannot be identified.
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
| Both fixed Ruby versions | Explicit `--prefix`, `--enable-shared`, `--enable-rpath`, `--enable-option-checking=fatal` |
| Ruby 3.4.12 | Explicit `--disable-yjit` and `--disable-rjit` |
| Ruby 4.0.9 | Explicit `--disable-yjit` and `--disable-zjit` |
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
succeed; a record alone never proves a healthy installation.

| Observed state | Required behavior |
| --- | --- |
| Prefix absent; inputs, environment and publication paths valid | Install into the new dedicated prefix |
| Dedicated empty prefix with suitable ownership, permissions and parent path | Permit new installation; unrelated content instead causes a stop |
| Same version/build contract, valid record and healthy files | No download, configure, make, dependency installation, CRB change or workspace creation; inspect links separately |
| Same version but source digest, shared-library/JIT policy or documentation differs | Stop before host changes; do not rebuild or adjust documents |
| Ruby exists but record is missing, unreadable, incomplete or inconsistent with placement | Stop; do not adopt unmanaged files |
| Record exists but Ruby is missing or broken | Stop as incomplete installation and preserve files |
| Different version in the same prefix | Stop; no upgrade, downgrade or overwrite |
| Partial, corrupt, non-executable installation or missing required functionality | Stop; no automatic repair |
| OS Ruby outside the managed prefix without path conflicts | Preserve it and allow coexistence |
| Conflicting paths, unsupported environment or invalid inputs | Stop before dependencies, CRB or managed-path changes |
| A different new prefix is requested while an old prefix remains | Assess the new prefix independently; preserve old prefix/links and stop on publication conflicts |
| Build or installation fails partway | Report failure and possible partial prefix; do not finalize a successful record; a later run must reject incomplete state |

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

Links are disabled by default. When explicitly enabled, publish selected allowed
commands to `/usr/local/bin/<command>`, resolving to the corresponding healthy
`<prefix>/bin/<command>`. Inspect all selected sources/destinations before creating
any link. Do not install additional gems to conceal a missing command.

| Setting/state | Required behavior |
| --- | --- |
| Links disabled and no applicable existing publication | Leave external paths unchanged |
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

The required Role matrix has six conditions, each including installation,
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
candidates and release candidates; separate checks that do not require builds.

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
| T15 | Every old name, wrong types, invalid versions, checksum/URL errors, command-list errors, invalid/overlapping/shared/unsafe paths, unwritable or missing workspace and known noexec; valid-input controls also pass |

The initial full-Role test planning basis is target CPU1, memory limit 2 GiB,
no additional swap, make jobs 1, one condition at a time and no automatic retries.
This does not limit the public build-jobs input to 1 or guarantee host RAM needs.
The initial planning allowance is 1500 credits and a 20-minute stop-decision
threshold per build condition. Before any run, check current pricing, balance,
resource class and the complete job estimate, and implement timeout/child-process
termination, failure evidence and cleanup. These values are not billing caps or
authorization to trigger CI; do not silently shrink required coverage to fit.

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

Role `v1.0.0` is distinct from Ruby 3.4.12 or 4.0.9. The adopted release identifiers
are Redmine Version `1.0.0` and Git tag `v1.0.0`, with a GitHub Release. These names
do not imply that the Version, tag or Release exists. Tickets are grouped by
target version; `release_tag` remains unused. Galaxy publication is deferred.

Public names, types, defaults, permitted values, semantics, supported environment,
state decisions and failure boundaries form the compatibility contract. Use a
major release for incompatible changes, minor for compatible additions or
deprecation notices, and patch for compatible fixes. Judge default changes by
their actual compatibility: a Ruby patch update does not automatically make a
Role default-version change compatible, since it can stop an existing prefix.

Before release, align defaults/tasks/metadata, examples, CHANGELOG, required tests
and this contract; verify distribution from the fixed ref in another directory.
Phase 1 completion requires the adopted references, P1-01 through P1-05 evidence
and repository contract to be reconciled. Phase 2 implementation has not started
in this documentation proposal. P1-06, human confirmation of copyright ownership,
code provenance and LICENSE text, is required before publication, not before
Phase 2. None of the evaluation evidence establishes release readiness.

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

## License status

The adopted identifier for the future release is **BSD-3-Clause**. The earlier
README said only `BSD`, and current metadata says `license (BSD, MIT)`. Human
confirmation of ownership/provenance and the final LICENSE text is still pending.
This README does not settle those conflicting labels or create a license grant.

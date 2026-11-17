# Phase 1 evaluation evidence

This is a public summary of historical evaluations for the v0.1.0 development
snapshot, prepared from retained results on 2026-11-17. It is not candidate CI
evidence and does not demonstrate execution of the new Role contract.

Specification baseline: [55a7ebfa6c6358ea03563d9ab6741921b2be03dc](https://github.com/ansible-roles-mamono210/ruby_install/commit/55a7ebfa6c6358ea03563d9ab6741921b2be03dc).
The snapshot retains later evaluation scripts/tests; individual historical runs
used the commits below. Do not substitute the snapshot SHA for their source SHA.
The candidate guard compares all paths with the baseline and permits seven
distribution-document/config paths plus three hash-pinned workflow-test paths
to differ. The three tests add the new exclusion and mixed-parameter coverage;
evaluation scripts and all other tests remain unchanged. This preserves the
original build/acquisition measurements at their original source commits; only
the candidate's CI-condition regression assertions need to be rerun.
That does not claim all old probe
revisions are byte-identical to the latest scripts.

## Build conditions and retained artifacts

All listed builds used make jobs 1 and the fixed CentOS Stream 9 x86_64 image
`ghcr.io/docker-images-mamono210/ansible-test/centos-stream9@sha256:96fbd1eac7c972466192da5183e80deeacd226332265d1698b2581bf7666ccd2`.
The original six conditions are CI422/424/426/428/434/436. CI438/440 are
additional Rust-present memory diagnostics, not two new independent conditions.

| CI | Ruby / documentation / Rust | Prefix | Source commit | Retained environment.json SHA-256 |
| --- | --- | --- | --- | --- |
| [422](https://app.circleci.com/pipelines/github/ansible-roles-mamono210/ruby_install/422) | 3.4.12 / ON / absent | `/opt/ruby` | `2e430a973cd30dbe464183d060df0af72cd204d7` | Unavailable; saved execution summary only |
| [424](https://app.circleci.com/pipelines/github/ansible-roles-mamono210/ruby_install/424) | 3.4.12 / OFF / absent | `/opt/ruby-3.4.12-docs-off` | `904f1dfcd4a8b59dfec1425f8dcb2404bf74fcd5` | `891f033f30539444ee593eae584e3cf6d6feb399e5171c69ff028c74f93c97a1` |
| [426](https://app.circleci.com/pipelines/github/ansible-roles-mamono210/ruby_install/426) | 4.0.9 / ON / absent | `/opt/ruby` | `f45764a46c0ef30a0cf2dc0d021f4e4619ffb231` | `4fa16ed84114b5bd97e99fca7fcf0ddc105c8f5c32cf369dc82e4282eb1e55e8` |
| [428](https://app.circleci.com/pipelines/github/ansible-roles-mamono210/ruby_install/428) | 4.0.9 / OFF / absent | `/opt/ruby-4.0.9-docs-off` | `8687d152bb36492ec5ae4d45e4087b122a9a8198` | `be23e7db00433af1ad8d7dbc13c1b255c561610af0788a805af156f0655cedcc` |
| [434](https://app.circleci.com/pipelines/github/ansible-roles-mamono210/ruby_install/434) | 3.4.12 / ON / present | `/opt/ruby` | `d6df2504a9d41ae881c9577bef19c670f1e50a3d` | `7ad81199ec5f61586dab663e94e58c7c10d4e40570a0fbb7fb270ed1e5d5a9f1` |
| [436](https://app.circleci.com/pipelines/github/ansible-roles-mamono210/ruby_install/436) | 4.0.9 / ON / present | `/opt/ruby` | `6b987775f694a6565614ee6c6ab6017b21a6d858` | `3de276d3c44c90124197358fc83b36bf9303c22db019717806f19213f41a383d` |
| [438](https://app.circleci.com/pipelines/github/ansible-roles-mamono210/ruby_install/438) | 4.0.9 / ON / present | `/opt/ruby` | `b22e02d6e3ee5d8bc781fddb70a7a39a135b354b` | `5fec3697f2f2fc300fd8c495fed0bd7e6905dcaa4f7fbd5b63bc4377190fe8b1` |
| [440](https://app.circleci.com/pipelines/github/ansible-roles-mamono210/ruby_install/440) | 3.4.12 / ON / present | `/opt/ruby` | `c2c3f74f9223a027a0ee0409e283309a1f409c2b` | `13202568ee0537c4741046926bac5451ae653fd4cd99b0ad92ca4aae32b216fc` |

Seven retained JSON files were rehashed and their conditions, configure arguments,
successful build flags and cleanup flags read during this preparation. Those
hashes identify retained UTF-8 JSON, not an independently verified byte-for-byte
copy of an original HTTP download. CI422's original JSON was not available for
this check. The linked CircleCI pages may require access and artifact retention;
this summary cannot reconstruct the complete measurements or raw logs.

All seven inspected argv lists include `--enable-option-checking=fatal`, explicit
prefix, shared libraries, rpath, `--disable-yjit` and `--disable-install-capi`.
Ruby 3.4 uses `--disable-rjit`; 4.0 uses `--disable-zjit`. Documentation ON adds
`--enable-install-doc --enable-install-rdoc`; OFF uses `--disable-install-doc`.
These evaluated controls are now in the adopted contract. Nine commands,
shared-library and standard-extension behavior were evaluation checks, not proof
of the future Role's state machine.

The retained measurements reproduce the adopted sampled maxima:

| Measurement | Bytes | Source |
| --- | ---: | --- |
| Workspace allocation | 882941952 | CI436 |
| Prefix allocation | 142110720 | CI434 and CI440 |
| Simultaneous workspace + prefix allocation | 1023119360 | CI436 |

Sampling was every five seconds. A simultaneous maximum is not the sum of two
independent maxima. The 2 GiB shared-filesystem threshold, or 2 GiB workspace
and 512 MiB prefix thresholds on different filesystems, include margin and are
not a separate-filesystem measurement. Rust-present memory peaks reached the
2 GiB limit with recorded OOM counters zero; this is not a universal RAM guarantee.
The historical six-job total of 42m47s / 427.8 credits is planning history, not
current pricing or approval to spend credits on the candidate.

## Acquisition and noexec

| CI | Fixed source commit | Retained environment.json SHA-256 | Result and limits |
| --- | --- | --- | --- |
| [446](https://app.circleci.com/pipelines/github/ansible-roles-mamono210/ruby_install/446) | `e5bf31f83edc44675537cdb08d41dcd6d5cca288` | `dfb893c84583f7b25d036cfa97e1a30261e8d27588febb58c1ed09152a5de0c3` | Exec control and noexec refusal using the same ELF/coreutils binary; not whole-Role preflight or SELinux validation. |
| [454](https://app.circleci.com/pipelines/github/ansible-roles-mamono210/ruby_install/454) | `0c8fbcc611271ea0c2e31bfe02615b05766e24af` | `2fb2ce97251a2ec91cea32b16755d40b61b3f8a42fd9035e856eb691bb80d054` | 16 actual Ansible acquisition cases; only valid input reached the gate; redirect destination connection/request deltas zero; cleanup recorded. |

CI454 used controller Python 3.14.10/core 2.21.6 and target CS9/Python 3.9.19,
UID65534, a fixture CA and a five-second timeout. Cases were valid download,
checksum mismatch, 300/301/302/303/307/308 redirects to HTTP and HTTPS, untrusted
certificate and hostname mismatch. This was a loopback fixture; root execution,
system CA and official Ruby download/build through the Role remain future work.
Historical `role_verified`, `p1_04_complete` and `phase1_complete` false flags
remain unchanged. Later specification adoption is separate from those flags.

## Naming and fixed evaluation environments

CI452 at `ea61c6e8362f5cc0fd27dbc4239f5a220e3c0476` detected the four legacy
names actually present in defaults and accepted the renamed control. Its eight
cases and cleanup are referenced from the saved execution record; its original
artifact has not been revalidated for this ledger. This is not whole-Role lint.

The proposed candidate uses the same selected controller/lint digests listed
in [the release notes](releases/v0.1.0.md). Historical evaluation environments,
including dependencies/CRB/PATH, do not establish legacy Role compatibility or
the future module's target-Python coverage. The controller/lint candidate jobs
still need actual fixed-image execution and final candidate retrieval.

The repository contains 21 regression files with 582 statically counted methods.
Candidate execution must record actual collection, results and skips, and require
the six real lint methods on the lint job. Those tests are separate from the
16 CI454 acquisition cases and from the Ruby build conditions. The ledger does
not sum them into one acceptance count.

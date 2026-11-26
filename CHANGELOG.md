# Changelog

## Unreleased — v1.0.0

- Add a release check against a Ruby installation and two command links created
  by the published v0.3.0 Role. Verify the installer revision and the Role
  used in each rerun. The six fresh candidate installations remain part of CI.
- Add [fixed-revision installation, migration and recovery examples](docs/releases/v1.0.0.md).

## v0.3.0 — 2026-11-23 (JST)

- Publish selected Ruby commands under `/usr/local/bin` when enabled. The
  default remains off. A healthy v0.2.0 installation can add links without
  rebuilding Ruby or rewriting its schema-1 record.
- Check all selected sources and destinations before creating links. Reuse
  matching links and report the created and outstanding names on a partial
  failure. Disabling links or reducing the list detects remaining links.
- The normal CI installation starts from the pinned v0.2.0 tag. The six release
  conditions install the candidate and compare its records with the published
  v0.2.0 observations. The Ruby 4.0.9 Rust-present condition also publishes
  commands during the first installation, then adds two more on a healthy rerun.
- [Published Pre-release](https://github.com/ansible-roles-mamono210/ruby_install/releases/tag/v0.3.0)
  at `0002dea544bfd6d52b4f0aaa94a4eff5aec54bd5`.
  [Normal CI #480](https://app.circleci.com/pipelines/github/ansible-roles-mamono210/ruby_install/480/workflows/0d37ed82-f0b0-4d1b-b2a1-498963fa3c2e)
  and [release CI #481](https://app.circleci.com/pipelines/github/ansible-roles-mamono210/ruby_install/481/workflows/c8bbe26e-c690-4a60-b397-02ab3415896d)
  passed at that revision.

## v0.2.0 — 2026-11-22

- Replace the four legacy defaults with ten public inputs. Reject the five
  documented legacy names when visible, including null values.
- Check native types, positive build parallelism and the selected command
  list. Resolve the version, HTTPS source, SHA-256 and absolute paths.
- Inspect existing prefixes and records without modifying them. Only new
  candidates require the build workspace and space allowance.
- Resolve build dependencies and enable CRB when required. Download, verify
  and validate the Ruby archive, build and install it in a dedicated prefix,
  then verify all nine commands, native libraries and the documentation setting.
- Publish a completed installation record only after the checks pass. Remove
  the current successful workspace by default and retain diagnostics on failure.
- Check the managed Ruby and required libraries on recorded reruns, and look
  for remaining public links when publication is disabled. Link creation is
  scheduled for v0.3.0.
- Verified six real installations across Ruby 3.4.12 and 4.0.9 at `d9289758`.
  The [published Pre-release](https://github.com/ansible-roles-mamono210/ruby_install/releases/tag/v0.2.0)
  identifies the final commit and CI #477 and #478. The [release notes](docs/releases/v0.2.0.md)
  give the schema-1 installation record and manual recovery steps.

## v0.1.0 — specification and evaluation snapshot

### Included

- Adopted Phase 1 specification for the future Ruby installation Role, including
  strict public inputs, managed-prefix protection, verified acquisition, build
  policy and staged release boundaries.
- Existing evaluation scripts and 21 regression test files. Historical build,
  acquisition, noexec and lint-control evidence is indexed with fixed source
  references in [the evidence ledger](docs/p1-evidence.md).
- Explicit limited candidate checks, distribution documentation and metadata
  that avoids unsupported minimum-version and general EL claims.

### Limits

The legacy `tasks/main.yml`, `defaults/main.yml` and `molecule/default` remain
unchanged. They do not implement the new Role contract. Evaluation results are
not proof of Role installation, healthy reruns, record creation or link safety.
The main-branch badge is not a v0.1.0 candidate result.

Three existing test files cover the new workflow exclusion and all parameter
combinations. The runtime host mock follows the configured temporary directory
instead of assuming `/tmp` directly. Evaluation scripts and other tests are
unchanged. No prior build result is reassigned to a new source commit.

The BSD-3-Clause LICENSE and matching metadata are included. The holder confirmed
the existing code was self-written and selected `mamono210`, with 2021 from the
repository's initial commit, for the copyright notice. This replaces the earlier
ambiguous license labels. CI462 passed on
`2b4f9a397f3ad9e23001eee6ddcc260533aa0ad9`; the exact checks and limits are
recorded in [the release notes](docs/releases/v0.1.0.md). The published
Pre-release identifies the final approved SHA and its verification record.
These notes do not by themselves assert that a tag or Release exists.

### Following releases

- v0.2.0: Phases 2+3 installation, records, healthy reruns and protection.
  Link-ON input stops before changes; disabled-link residual protection remains.
- v0.3.0: Phase 4 link publication and compatibility with v0.2.0 records.
- v1.0.0: full contract, compatibility, documentation and release validation.

The six real-Role conditions and normal four CI categories remain requirements
for v0.2.0 and later. The v0.1.0 boundary does not remove those requirements.

# Changelog

## Unreleased — v0.2.0 development

- Replace the four legacy defaults with ten public inputs. Reject the five
  documented legacy names when visible, including null values.
- Check native types, positive build parallelism and the selected command
  list. Stop link requests and all installation attempts before host inspection
  while the remaining preflight stages are under development.

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

# Changelog

## v0.1.0 — in preparation, not published

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

Three existing workflow-condition tests are updated to require the new exclusion
and exercise all parameter combinations; evaluation scripts and other tests are
unchanged. No prior build result is reassigned to a new source commit.

The BSD-3-Clause LICENSE and matching metadata are included. The holder confirmed
the existing code was self-written and selected `mamono210`, with 2021 from the
repository's initial commit, for the copyright notice. This replaces the earlier
ambiguous license labels. Candidate SHA, fixed-image CI results, tag retrieval
and GitHub Pre-release publication are pending.

### Following releases

- v0.2.0: Phases 2+3 installation, records, healthy reruns and protection.
  Link-ON input stops before changes; disabled-link residual protection remains.
- v0.3.0: Phase 4 link publication and compatibility with v0.2.0 records.
- v1.0.0: full contract, compatibility, documentation and release validation.

The six real-Role conditions and normal four CI categories remain requirements
for v0.2.0 and later. The v0.1.0 boundary does not remove those requirements.

#!/usr/bin/env bash
# Run one condition on a dedicated CircleCI machine from the role checkout.
set -euo pipefail
controller="ruby-install-controller-${CIRCLE_BUILD_NUM:?}"
target=ruby-install-default
condition=${3:-3.4.12-default}
if [[ ! $condition =~ ^(3\.4\.(12|13)|4\.0\.(9|10))-(default|custom|rust)$ ]]; then
  echo "Unsupported condition: $condition" >&2
  exit 2
fi
case "${4:-candidate}" in
  candidate) installer_role=candidate ;;
  --from-v020|v0.2.0)
    installer_role=v0.2.0
    baseline_name=ruby_install_v020
    baseline_sha=6b1cd945c5a0d3472c7f1dfe565852db37097596
    ;;
  v0.3.0)
    installer_role=v0.3.0
    baseline_name=ruby_install_v030
    baseline_sha=0002dea544bfd6d52b4f0aaa94a4eff5aec54bd5
    ;;
  v1.0.0)
    [[ "$condition" == 3.4.12-default ]] || { echo "v1.0.0 requires 3.4.12-default" >&2; exit 2; }
    installer_role=v1.0.0
    baseline_name=ruby_install_v100
    baseline_sha=057658e284ae63769722d0c47116b41fb0e5b3f6
    ;;
  *) echo "Unsupported installer: $4" >&2; exit 2 ;;
esac
commit=$(git rev-parse HEAD)
test "$commit" = "${CIRCLE_SHA1:?}"
evidence="$HOME/ruby-install-default-evidence"
mkdir -p "$evidence"
printf '%s\n' "$condition" > "$evidence/condition.txt"
printf '%s\n' "$commit" > "$evidence/commit.txt"
printf '%s\n' "$commit" > "$evidence/installer-commit.txt"
started=$SECONDS
baseline_root=""
baseline_args=()
existing=$(docker container ls -a --format '{{.Names}}')
for name in "$target" "$controller"; do
  if grep -Fxq "$name" <<<"$existing"; then
    echo "Molecule container already exists: $name" >&2
    exit 1
  fi
done

finish() {
  status=$?
  trap - EXIT
  set +e
  if docker container inspect "$target" >/dev/null 2>&1; then
    docker inspect --format '{{json .State}}' "$target" > "$evidence/target-state.json"
    docker inspect --format '{{.HostConfig.NanoCpus}} {{.HostConfig.Memory}} {{.HostConfig.MemorySwap}} {{.HostConfig.CpuPeriod}} {{.HostConfig.CpuQuota}}' \
      "$target" > "$evidence/target-limits.txt"
    timeout 8s docker exec "$target" sh -c 'cat /sys/fs/cgroup/memory.events 2>/dev/null || cat /sys/fs/cgroup/memory/memory.oom_control' \
      > "$evidence/memory.txt" 2>/dev/null
    timeout 8s docker exec "$target" sh -ec '
      cd /sys/fs/cgroup
      if test -f cgroup.controllers; then
        echo v2
        cat cpu.max memory.max memory.swap.max
      else
        cpu=cpu
        test -r "$cpu/cpu.cfs_quota_us" || cpu=cpu,cpuacct
        echo v1
        cat "$cpu/cpu.cfs_quota_us" "$cpu/cpu.cfs_period_us" memory/memory.limit_in_bytes memory/memory.memsw.limit_in_bytes
      fi' > "$evidence/cgroup-limits.txt"
    timeout 8s docker exec "$target" sh -c '
      for peak in /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory/memory.max_usage_in_bytes; do
        if test -r "$peak"; then cat "$peak"; break; fi
      done' > "$evidence/memory-peak-bytes.txt"
    if [[ "$installer_role" == v1.0.0 ]] &&
        ! docker cp "$target:/var/tmp/ruby-install-version-mismatch.json" "$evidence/version-mismatch.json"; then
      (( status != 0 )) || status=1
    fi
    if (( status == 0 )); then
      docker cp "$target:/var/tmp/ruby-install-case.json" "$evidence/case.json" &&
        python3 molecule/default/check_evidence.py "$evidence" "$condition" "$commit" --installer "$installer_role" || status=1
    fi
    if (( status != 0 )); then
      timeout 8s docker exec "$target" sh -c '
        for log in /tmp/ruby-install-*/configure.log /tmp/ruby-install-*/build.log /tmp/ruby-install-*/install.log; do
          if test -f "$log"; then echo "$log"; tail -c 8192 "$log"; fi
        done' > "$evidence/build-log-tails.txt"
    fi
  elif (( status == 0 )); then
    echo "Target evidence unavailable" >&2
    status=1
  fi
  for name in "$controller" "$target"; do
    if docker container inspect "$name" >/dev/null 2>&1; then
      timeout 30s docker rm -f "$name" >/dev/null || status=1
    fi
  done
  if [[ -n "$baseline_root" ]]; then
    rm -rf -- "$baseline_root" || status=1
  fi
  remaining=$(docker container ls -a --format '{{.Names}}') || status=1
  for name in "$controller" "$target"; do
    if grep -Fxq "$name" <<<"$remaining"; then status=1; fi
  done
  echo "$((SECONDS - started))" > "$evidence/elapsed-seconds.txt"
  echo "$status" > "$evidence/exit-code.txt"
  exit "$status"
}
trap finish EXIT
if [[ "$installer_role" != candidate ]]; then
  baseline_root=$(mktemp -d)
  baseline="$baseline_root/$baseline_name"
  (
    umask 022
    git init -q "$baseline"
    git -C "$baseline" fetch -q --no-tags --depth 1 "$(git remote get-url origin)" "refs/tags/$installer_role"
    git -C "$baseline" checkout -q --detach FETCH_HEAD
    test "$(git -C "$baseline" rev-parse HEAD)" = "$baseline_sha"
  )
  git -C "$baseline" rev-parse HEAD > "$evidence/installer-commit.txt"
  baseline_args=(-v "$baseline:/tmp/$baseline_name:ro")
fi
timeout --signal=TERM --kill-after=20s 20m docker run --name "$controller" \
  "${baseline_args[@]}" \
  -e "RUBY_INSTALL_TEST_COMMIT=$commit" \
  -e "RUBY_INSTALL_TEST_INSTALLER=$installer_role" \
  -e "MOLECULE_IMAGE=$2" -e "RUBY_INSTALL_MATRIX_CASE=$condition" -v "$PWD":/tmp/ruby_install:ro -w /tmp/ruby_install \
  -v /usr/bin/docker:/usr/bin/docker -v /var/run/docker.sock:/var/run/docker.sock \
  "$1" molecule test --destroy=never --scenario-name default 2>&1 | tee "$evidence/molecule.log"

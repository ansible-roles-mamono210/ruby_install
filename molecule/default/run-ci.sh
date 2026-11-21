#!/usr/bin/env bash
# Run on the dedicated CircleCI machine from the role checkout.
set -euo pipefail
controller="ruby-install-controller-${CIRCLE_BUILD_NUM:?}"
target=ruby-install-default
evidence="$HOME/ruby-install-default-evidence"
mkdir -p "$evidence"
# Reserve names before installing the cleanup trap.
for name in "$target" "$controller"; do
  if docker container inspect "$name" >/dev/null 2>&1; then
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
    timeout 8s docker exec "$target" sh -c 'cat /sys/fs/cgroup/memory.events 2>/dev/null || cat /sys/fs/cgroup/memory/memory.oom_control' \
      > "$evidence/memory.txt" 2>/dev/null
    if [[ "$(docker inspect --format '{{.State.OOMKilled}}' "$target")" == true ]] ||
       grep -Eq '^oom_kill [1-9][0-9]*$' "$evidence/memory.txt"; then
      echo "Target OOM kill recorded" >&2
      status=1
    fi
    if (( status != 0 )); then
      timeout 8s docker exec "$target" sh -c '
        for log in /tmp/ruby-install-*/configure.log /tmp/ruby-install-*/build.log /tmp/ruby-install-*/install.log; do
          if test -f "$log"; then echo "$log"; tail -c 8192 "$log"; fi
        done' > "$evidence/build-log-tails.txt"
    fi
  fi
  for name in "$controller" "$target"; do
    if docker container inspect "$name" >/dev/null 2>&1; then
      docker rm -f "$name" >/dev/null || status=1
    fi
  done
  echo "$status" > "$evidence/exit-code.txt"
  exit "$status"
}
trap finish EXIT
timeout --signal=TERM --kill-after=20s 20m docker run --name "$controller" \
  -e "MOLECULE_IMAGE=$2" -v "$PWD":/tmp/ruby_install:ro -w /tmp/ruby_install \
  -v /usr/bin/docker:/usr/bin/docker -v /var/run/docker.sock:/var/run/docker.sock \
  "$1" molecule test --destroy=never --scenario-name default 2>&1 | tee "$evidence/molecule.log"

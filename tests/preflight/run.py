"""Exercise the normal entry with inventory inputs. Requires ansible-playbook."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
PENDING = "PREFLIGHT_INCOMPLETE:"
INVALID = "INVALID_INPUT:"


def entry_cases():
    cases = {}

    def case(name, expected, **inputs):
        cases[name] = {"expected_reason": expected, **inputs}

    case("defaults", PENDING)
    for name in ("workspace", "ruby_version", "ruby_download_url", "ruby_make_prefix",
                 "ruby_source_configure_command"):
        case("legacy_" + name, "LEGACY_INPUT: " + name + ".", **{name: None})
    case("old_and_new", "LEGACY_INPUT: ruby_version.", ruby_version="",
         ruby_install_version="3.4.12")
    case("discarded_proposal_names", PENDING, ruby_build_jobs=False, ruby_download_checksum=42,
         ruby_create_symlinks=True, ruby_symlink_commands=0, ruby_keep_build_workspace=None)
    for name in ("version", "prefix", "workspace", "download_url", "download_checksum"):
        case("bad_" + name, INVALID, **{"ruby_install_" + name: 4})
    for name in ("documentation", "create_symlinks", "keep_build_workspace"):
        case("bad_" + name, INVALID, **{"ruby_install_" + name: "false"})
    for i, value in enumerate((True, "4", 0, -1, 1.5)):
        case("bad_jobs_" + str(i), INVALID, ruby_install_build_jobs=value)
    for i, value in enumerate(("ruby", {"ruby": True}, ["ruby", 1], ["gem", "gem"],
                               ["Ruby"], ["bin/ruby"])):
        case("bad_commands_" + str(i), INVALID, ruby_install_symlink_commands=value)
    case("empty_off", PENDING, ruby_install_symlink_commands=[], ruby_install_build_jobs=4)
    case("empty_on", INVALID, ruby_install_symlink_commands=[], ruby_install_create_symlinks=True)
    case("links_on", "LINKS_UNAVAILABLE:", ruby_install_create_symlinks=True)

    return cases


def main():
    cases = entry_cases()
    with tempfile.TemporaryDirectory() as dirname:
        root = Path(dirname)
        (root / "ruby_install").symlink_to(HERE.parents[1], target_is_directory=True)
        inventory = root / "inventory.yml"
        inventory.write_text(json.dumps({"all": {
            "vars": {"ansible_connection": "ssh", "ansible_ssh_executable": "/usr/bin/false"},
            "hosts": cases,
        }}))
        subprocess.run(["ansible-playbook", "-i", str(inventory), str(HERE / "entry.yml")],
                       env={**os.environ, "ANSIBLE_ROLES_PATH": dirname}, check=True)
    print(f"{len(cases)} entry cases passed")


if __name__ == "__main__":
    main()

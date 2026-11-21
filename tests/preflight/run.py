"""Exercise the normal entry with inventory inputs. Requires ansible-playbook."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
MISSING_FACTS = "UNSUPPORTED_TARGET:"
INVALID = "INVALID_INPUT:"


def entry_cases():
    cases = {}

    def case(name, expected, **inputs):
        cases[name] = {"expected_reason": expected, **inputs}

    case("defaults", MISSING_FACTS)
    for name in ("workspace", "ruby_version", "ruby_download_url", "ruby_make_prefix",
                 "ruby_source_configure_command"):
        case("legacy_" + name, "LEGACY_INPUT: " + name + ".", **{name: None})
    case("old_and_new", "LEGACY_INPUT: ruby_version.", ruby_version="",
         ruby_install_version="3.4.12")
    case("discarded_proposal_names", MISSING_FACTS, ruby_build_jobs=False, ruby_download_checksum=42,
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
    case("empty_off", MISSING_FACTS, ruby_install_symlink_commands=[], ruby_install_build_jobs=4)
    case("empty_on", INVALID, ruby_install_symlink_commands=[], ruby_install_create_symlinks=True)
    case("links_on", "LINKS_UNAVAILABLE:", ruby_install_create_symlinks=True)

    for i, value in enumerate(("3.4", "3.4.12-rc1", "4.1.0", "", "latest", ">=3.4", 3.4)):
        case("invalid_version_" + str(i), INVALID, ruby_install_version=value)
    case("unknown_digest", INVALID, ruby_install_version="3.4.99")
    case("explicit_url_needs_digest", INVALID, ruby_install_download_url="https://example.org/ruby")
    case("relative_prefix", INVALID, ruby_install_prefix="opt/ruby")
    case("shared_prefix", INVALID, ruby_install_prefix="/usr/local")
    case("overlap", INVALID, ruby_install_prefix="/opt/ruby", ruby_install_workspace="/opt/ruby/tmp")
    case("valid_custom", MISSING_FACTS, ruby_install_version="4.0.10",
         ruby_install_download_url="https://example.org/ruby", ruby_install_download_checksum="sha256:" + "1" * 64)

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
        command = ["ansible-playbook", "-i", str(inventory), str(HERE / "entry.yml")]
        env = {**os.environ, "ANSIBLE_ROLES_PATH": dirname}
        subprocess.run(command, env=env, check=True)

        typed = {"ruby_install_build_jobs": 4, "ruby_install_documentation": False}
        vars_file = root / "typed.yml"
        vars_file.write_text("ruby_install_build_jobs: 4\nruby_install_documentation: false\n")
        extra_cases = [
            ("@" + str(vars_file), MISSING_FACTS),
            (json.dumps(typed), MISSING_FACTS),
            ("ruby_install_build_jobs=4", INVALID),
            ("ruby_install_documentation=false", INVALID),
        ]
        for argument, reason in extra_cases:
            subprocess.run(command + ["--limit", "defaults", "-e", argument,
                                      "-e", json.dumps({"expected_reason": reason})], env=env, check=True)
    print(f"{len(cases)} inventory and {len(extra_cases)} extra-variable entry cases passed")


if __name__ == "__main__":
    main()

"""Loopback sources for the Role's redirect, checksum and failure-workspace checks."""
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import ssl
import stat
import sys
import tarfile
import time

from download_guard_fixture import barrier, certificate_material, serving


def configure_failure_archive():
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name, body in (("configure", b"#!/bin/sh\necho fixture-configure-failure\nexit 23\n"),
                           ("configure.ac", b"fixture\n"), ("version.h", b"fixture\n")):
            info = tarfile.TarInfo("ruby-3.4.12/" + name)
            info.size = len(body)
            info.mode = 0o755 if name == "configure" else 0o644
            archive.addfile(info, io.BytesIO(body))
    return data.getvalue()


def check_workspace(root, name, body):
    parent = root / name
    entries = list(parent.glob("ruby-install-*"))
    if (len(entries) != 1 or entries[0].lstat().st_mode != (stat.S_IFDIR | 0o700)
            or (parent / "sibling.txt").read_bytes() != b"preserve\n" or os.path.lexists(root / "new-prefix")):
        raise ValueError(name + ": retained workspace, sibling or prefix differs")
    work = entries[0]
    if name == "configure":
        if b"fixture-configure-failure" not in (work / "configure.log").read_bytes() or (work / "install.log").exists():
            raise ValueError("missing configure diagnostic or unexpected installation")
    else:
        if (work / "source").exists() or (work / "build").exists():
            raise ValueError(name + ": source processing started")
        archive = work / "source.tar.gz"
        if name == "wrong_digest":
            if archive.read_bytes() != body:
                raise ValueError("missing downloaded bytes from the checksum stop")
        elif archive.exists():
            raise ValueError(name + ": a redirect produced a source archive")


def serve(root):
    os.umask(0o077)
    certificate, key = certificate_material()
    ca, key_file = root / "ca.pem", root / "key.pem"
    ca.write_text(certificate)
    key_file.write_text(key)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        tls.load_cert_chain(str(ca), str(key_file))
    finally:
        key_file.unlink()
    client = ssl.create_default_context(cafile=str(ca))
    body = configure_failure_archive()
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    with ExitStack() as stack:
        http = stack.enter_context(serving())
        https = stack.enter_context(serving(tls))
        hop = stack.enter_context(serving())
        sinks = [(http, None), (https, client), (hop, None)]
        counts = [barrier(server, ctx) for server, ctx in sinks]
        hop.reply = (302, f"https://localhost:{https.server_port}/last", b"")
        redirects = {"to_http": f"http://localhost:{http.server_port}/sink",
                     "to_https": f"https://localhost:{https.server_port}/sink",
                     "via_http": f"http://localhost:{hop.server_port}/middle"}
        origins, cases = {}, []
        for name in ("wrong_digest", *redirects, "configure"):
            origin = stack.enter_context(serving(tls))
            origins[name] = origin
            origin.reply = (302, redirects[name], b"") if name in redirects else (200, None, body)
            (root / name).mkdir()
            (root / name / "sibling.txt").write_bytes(b"preserve\n")
            reason = "Download the source directly over verified HTTPS failed."
            if name == "wrong_digest":
                reason = "SOURCE_CHECKSUM_MISMATCH:"
            elif name == "configure":
                reason = "BUILD_FAILED:"
            cases.append({"name": name, "url": f"https://localhost:{origin.server_port}/source",
                          "checksum": "sha256:" + "0" * 64 if name == "wrong_digest" else digest, "reason": reason})
        tmp = root / "ready.tmp"
        tmp.write_text(json.dumps(cases))
        tmp.rename(root / "ready.json")
        deadline = time.monotonic() + 240
        while not (root / "stop").exists():
            if time.monotonic() > deadline:
                raise TimeoutError("Role acquisition fixture timed out")
            time.sleep(0.1)
        for (sink, _), before in zip(sinks, counts):
            if (sink.accepted, sink.requests) != before:
                raise ValueError("redirect destination was contacted")
        for name, origin in origins.items():
            if origin.requests != 1:
                raise ValueError(name + ": expected one source request")
            check_workspace(root, name, body)
    print("Five expected Role stops. Each source received one request. Redirect destinations received zero "
          "connections or requests. All five private workspaces and sibling files survived. "
          "The configure log contains the expected failure.")


if __name__ == "__main__":
    serve(Path(sys.argv[1]))

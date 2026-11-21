"""Resolve the Role's inputs on the controller, without filesystem or network access."""
import ipaddress
import posixpath
import re
from urllib.parse import unquote, urlsplit


CHECKSUMS = {
    "3.4.12": "5e5d85ad93b0adcccbad47733680f4892bd0078e3342437f7babce01c1872479",
    "4.0.9": "c35350682ff050b79702d57ade4516e7336063f510155d19fb2fb5b3f3909511",
}


def absolute_path(value):
    if (not isinstance(value, str) or not value.startswith("/")
            or ".." in value.split("/") or not value.isprintable()):
        raise ValueError("prefix and workspace must be absolute paths without parent traversal or control characters")
    return posixpath.normpath("/" + value.lstrip("/"))


def source(version, url, checksum):
    if not isinstance(version, str) or not re.fullmatch(r"(?:3\.4|4\.0)\.(?:0|[1-9][0-9]*)", version):
        raise ValueError("ruby_install_version requires a full stable 3.4.N or 4.0.N version")
    if not isinstance(url, str) or not isinstance(checksum, str):
        raise ValueError("download URL and checksum must be strings")
    path = "/pub/ruby/{}/ruby-{}.tar.gz".format(version.rsplit(".", 1)[0], version)
    host = "cache.ruby-lang.org"
    expected = CHECKSUMS.get(version)
    official = True
    if url:
        try:
            if not url.isprintable() or any(c.isspace() for c in url) or "\\" in url:
                raise ValueError
            parts = urlsplit(url)
            hostname = parts.hostname
            port = parts.port
            if (parts.scheme != "https" or not hostname or parts.username is not None
                    or parts.password is not None or parts.netloc.endswith(":") or port == 0):
                raise ValueError
            if "[" in parts.netloc or "]" in parts.netloc:
                if not re.fullmatch(r"\[[^\]]+\](?::[0-9]+)?", parts.netloc):
                    raise ValueError
                ipaddress.IPv6Address(hostname)
            else:
                labels = hostname.rstrip(".").encode("idna").decode("ascii").split(".")
                if not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", s) for s in labels):
                    raise ValueError
            official = (hostname.lower().rstrip(".") == host and port in (None, 443)
                        and posixpath.normpath("/" + unquote(parts.path).lstrip("/")) == path)
        except (UnicodeError, ValueError):
            raise ValueError("ruby_install_download_url requires a valid HTTPS URL without embedded credentials") from None
    if checksum:
        if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", checksum):
            raise ValueError("ruby_install_download_checksum requires sha256: and 64 hex digits")
        digest = checksum[7:].lower()
        if expected and official and digest != expected:
            raise ValueError("checksum differs from the registered official tar.gz")
    elif not url and expected:
        digest = expected
    else:
        raise ValueError("an explicit URL or unregistered Ruby version requires an explicit checksum")
    return url or "https://" + host + path, digest


def resolve_inputs(version, url, checksum, prefix, workspace):
    try:
        url, digest = source(version, url, checksum)
        prefix = absolute_path(prefix)
        workspace = absolute_path(workspace)
        if prefix in ("/", "/usr", "/usr/local", "/opt"):
            raise ValueError("ruby_install_prefix must be a dedicated installation directory")
        if posixpath.commonpath((prefix, workspace)) in (prefix, workspace):
            raise ValueError("prefix and workspace must not contain one another")
    except ValueError as exc:
        # Errors describe fields, never the supplied URL, query or credential.
        return {"error": "INVALID_INPUT: " + str(exc)}
    return {"error": "", "url": url, "sha256": digest, "prefix": prefix, "workspace": workspace}


class FilterModule:
    def filters(self):
        return {"ruby_install_resolve_inputs": resolve_inputs}
